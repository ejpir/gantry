package netpol

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/miekg/dns"
)

const (
	// TrafficFileName is stored in each sandbox directory and intentionally
	// survives stop/resume cycles alongside sandbox.json.
	TrafficFileName         = "network-traffic.json"
	trafficSnapshotVersion  = 1
	maxTrafficEntries       = 512
	maxTrafficDNSNames      = 4096
	maxTrafficHostBytes     = 253
	maxTrafficAddressBytes  = 64
	maxTrafficProtocolBytes = 16
)

// TrafficSnapshot is the on-disk, read-only dashboard view of one VM's
// network activity. Byte and packet directions are from the guest's point of
// view: TX leaves the VM and RX enters it. Blocked traffic is counted in TX
// and separately in Dropped* because the guest did attempt to send it.
type TrafficSnapshot struct {
	Version        int            `json:"version"`
	Updated        time.Time      `json:"updated"`
	TXBytes        uint64         `json:"txBytes"`
	RXBytes        uint64         `json:"rxBytes"`
	TXPackets      uint64         `json:"txPackets"`
	RXPackets      uint64         `json:"rxPackets"`
	DroppedBytes   uint64         `json:"droppedBytes"`
	DroppedPackets uint64         `json:"droppedPackets"`
	Entries        []TrafficEntry `json:"entries"`
}

// TrafficEntry aggregates packets for a destination, protocol, port and
// policy decision. Host is a best-effort DNS name learned from responses;
// Address always retains the numeric peer address.
type TrafficEntry struct {
	Host      string    `json:"host"`
	Address   string    `json:"address"`
	Protocol  string    `json:"protocol"`
	Port      uint16    `json:"port,omitempty"`
	Allowed   bool      `json:"allowed"`
	TXBytes   uint64    `json:"txBytes"`
	RXBytes   uint64    `json:"rxBytes"`
	TXPackets uint64    `json:"txPackets"`
	RXPackets uint64    `json:"rxPackets"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

type trafficDNSName struct {
	host    string
	expires time.Time
}

// TrafficRecorder aggregates link traffic in memory and atomically publishes
// a bounded snapshot for the TUI. It never blocks packet processing on disk
// I/O: writes happen in a periodic background flush.
type TrafficRecorder struct {
	mu        sync.Mutex
	path      string
	snapshot  TrafficSnapshot
	entries   map[string]*TrafficEntry
	dnsNames  map[[4]byte]trafficDNSName
	dirty     bool
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// TrafficEpoch merges cumulative snapshots from one remote recorder into a
// lifetime TrafficRecorder. A worker reports counters from zero on every
// boot, while the supervisor recorder survives those boots on disk. Keeping
// the watermark in this trusted, per-worker object makes repeated periodic
// and final snapshots idempotent without trusting an epoch identifier supplied
// by the worker.
//
// Begin a new epoch for every new worker process and reuse it for every
// snapshot from that process.
type TrafficEpoch struct {
	recorder *TrafficRecorder
	previous trafficCounters
	entries  map[string]trafficEntryCounters
	mu       sync.Mutex
}

type trafficCounters struct {
	txBytes, rxBytes             uint64
	txPackets, rxPackets         uint64
	droppedBytes, droppedPackets uint64
}

type trafficEntryCounters struct {
	txBytes, rxBytes     uint64
	txPackets, rxPackets uint64
}

// NewTrafficRecorder starts a recorder at path. A valid previous snapshot is
// resumed so stop/start cycles retain the sandbox's traffic history.
func NewTrafficRecorder(path string) *TrafficRecorder {
	r := &TrafficRecorder{
		path:     path,
		snapshot: TrafficSnapshot{Version: trafficSnapshotVersion},
		entries:  make(map[string]*TrafficEntry),
		dnsNames: make(map[[4]byte]trafficDNSName),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if path == "" {
		// Confined workers use an in-memory recorder and expose snapshots over
		// RPC. Avoid a writer goroutine and ticker when there is no sink.
		close(r.done)
		return r
	}
	r.load()
	// Publish an empty marker immediately. The TUI uses its presence to
	// distinguish "no traffic yet" from a VM started by an older Gantry
	// binary that must be restarted to enable capture.
	r.dirty = true
	r.flush()
	go r.run()
	return r
}

// ReadTrafficSnapshot loads a snapshot without starting a recorder. A missing
// file is an empty snapshot, which keeps stopped and never-networked sandboxes
// inexpensive to render.
func ReadTrafficSnapshot(path string) (TrafficSnapshot, error) {
	var snapshot TrafficSnapshot
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return TrafficSnapshot{Version: trafficSnapshotVersion}, nil
	}
	if err != nil {
		return snapshot, err
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return TrafficSnapshot{}, err
	}
	if snapshot.Version != trafficSnapshotVersion {
		return TrafficSnapshot{}, nil
	}
	return snapshot, nil
}

func (r *TrafficRecorder) load() {
	snapshot, err := ReadTrafficSnapshot(r.path)
	if err != nil || snapshot.Version != trafficSnapshotVersion {
		return
	}
	r.snapshot = snapshot
	r.snapshot.Entries = nil
	for i := range snapshot.Entries {
		if len(r.entries) >= maxTrafficEntries {
			break
		}
		entry := snapshot.Entries[i]
		key := trafficEntryKey(entry.Address, entry.Host, entry.Protocol, entry.Port, entry.Allowed)
		copy := entry
		r.entries[key] = &copy
	}
}

func (r *TrafficRecorder) run() {
	ticker := time.NewTicker(time.Second)
	defer func() {
		ticker.Stop()
		r.flush()
		close(r.done)
	}()
	for {
		select {
		case <-ticker.C:
			r.flush()
		case <-r.stop:
			return
		}
	}
}

// Close publishes the final snapshot and stops the writer goroutine.
func (r *TrafficRecorder) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() { close(r.stop) })
	<-r.done
}

// BeginEpoch starts accumulation for one remote recorder lifetime. The epoch
// holds only bounded counter watermarks; the destination recorder owns the
// aggregate entries and persistence.
func (r *TrafficRecorder) BeginEpoch() *TrafficEpoch {
	if r == nil {
		return nil
	}
	return &TrafficEpoch{
		recorder: r,
		entries:  make(map[string]trafficEntryCounters),
	}
}

// Merge advances this epoch to other. Remote snapshots are cumulative within
// an epoch, so only monotonic deltas are added to the recorder's lifetime
// totals. Replays and stale snapshots add nothing; a new worker gets a new
// epoch and therefore contributes its counters from zero.
func (epoch *TrafficEpoch) Merge(other TrafficSnapshot) {
	if epoch == nil || epoch.recorder == nil || other.Version != trafficSnapshotVersion {
		return
	}
	epoch.mu.Lock()
	defer epoch.mu.Unlock()

	r := epoch.recorder
	r.mu.Lock()
	defer r.mu.Unlock()

	next := snapshotCounters(other)
	delta := next.delta(epoch.previous)
	epoch.previous = epoch.previous.max(next)
	if !delta.zero() {
		addSnapshotCounters(&r.snapshot, delta)
		r.dirty = true
	}

	entries := other.Entries
	if len(entries) > maxTrafficEntries {
		entries = entries[:maxTrafficEntries]
	}
	for _, e := range entries {
		if !validMergedTrafficEntry(e) {
			continue
		}
		key := trafficEntryKey(e.Address, e.Host, e.Protocol, e.Port, e.Allowed)
		cur, ok := r.entries[key]
		if !ok && len(r.entries) >= maxTrafficEntries {
			continue
		}
		next := entryCounters(e)
		previous := epoch.entries[key]
		delta := next.delta(previous)
		epoch.entries[key] = previous.max(next)

		if !ok {
			dup := e
			setEntryCounters(&dup, delta)
			r.entries[key] = &dup
			r.dirty = true
			continue
		}
		changed := !delta.zero()
		addEntryCounters(cur, delta)
		if e.FirstSeen.Before(cur.FirstSeen) {
			cur.FirstSeen = e.FirstSeen
			changed = true
		}
		if e.LastSeen.After(cur.LastSeen) {
			cur.LastSeen = e.LastSeen
			changed = true
		}
		if e.Host != "" && (cur.Host == "" || cur.Host == cur.Address) && e.Host != e.Address {
			cur.Host = e.Host
			changed = true
		}
		if changed {
			r.dirty = true
		}
	}
}

func snapshotCounters(snapshot TrafficSnapshot) trafficCounters {
	return trafficCounters{
		txBytes: snapshot.TXBytes, rxBytes: snapshot.RXBytes,
		txPackets: snapshot.TXPackets, rxPackets: snapshot.RXPackets,
		droppedBytes: snapshot.DroppedBytes, droppedPackets: snapshot.DroppedPackets,
	}
}

func entryCounters(entry TrafficEntry) trafficEntryCounters {
	return trafficEntryCounters{
		txBytes: entry.TXBytes, rxBytes: entry.RXBytes,
		txPackets: entry.TXPackets, rxPackets: entry.RXPackets,
	}
}

func (c trafficCounters) delta(previous trafficCounters) trafficCounters {
	return trafficCounters{
		txBytes:        monotonicDelta(c.txBytes, previous.txBytes),
		rxBytes:        monotonicDelta(c.rxBytes, previous.rxBytes),
		txPackets:      monotonicDelta(c.txPackets, previous.txPackets),
		rxPackets:      monotonicDelta(c.rxPackets, previous.rxPackets),
		droppedBytes:   monotonicDelta(c.droppedBytes, previous.droppedBytes),
		droppedPackets: monotonicDelta(c.droppedPackets, previous.droppedPackets),
	}
}

func (c trafficCounters) max(other trafficCounters) trafficCounters {
	return trafficCounters{
		txBytes: max(c.txBytes, other.txBytes), rxBytes: max(c.rxBytes, other.rxBytes),
		txPackets: max(c.txPackets, other.txPackets), rxPackets: max(c.rxPackets, other.rxPackets),
		droppedBytes:   max(c.droppedBytes, other.droppedBytes),
		droppedPackets: max(c.droppedPackets, other.droppedPackets),
	}
}

func (c trafficCounters) zero() bool {
	return c == (trafficCounters{})
}

func (c trafficEntryCounters) delta(previous trafficEntryCounters) trafficEntryCounters {
	return trafficEntryCounters{
		txBytes:   monotonicDelta(c.txBytes, previous.txBytes),
		rxBytes:   monotonicDelta(c.rxBytes, previous.rxBytes),
		txPackets: monotonicDelta(c.txPackets, previous.txPackets),
		rxPackets: monotonicDelta(c.rxPackets, previous.rxPackets),
	}
}

func (c trafficEntryCounters) max(other trafficEntryCounters) trafficEntryCounters {
	return trafficEntryCounters{
		txBytes: max(c.txBytes, other.txBytes), rxBytes: max(c.rxBytes, other.rxBytes),
		txPackets: max(c.txPackets, other.txPackets), rxPackets: max(c.rxPackets, other.rxPackets),
	}
}

func (c trafficEntryCounters) zero() bool {
	return c == (trafficEntryCounters{})
}

func monotonicDelta(current, previous uint64) uint64 {
	if current > previous {
		return current - previous
	}
	return 0
}

func addSnapshotCounters(snapshot *TrafficSnapshot, delta trafficCounters) {
	snapshot.TXBytes = saturatingAdd(snapshot.TXBytes, delta.txBytes)
	snapshot.RXBytes = saturatingAdd(snapshot.RXBytes, delta.rxBytes)
	snapshot.TXPackets = saturatingAdd(snapshot.TXPackets, delta.txPackets)
	snapshot.RXPackets = saturatingAdd(snapshot.RXPackets, delta.rxPackets)
	snapshot.DroppedBytes = saturatingAdd(snapshot.DroppedBytes, delta.droppedBytes)
	snapshot.DroppedPackets = saturatingAdd(snapshot.DroppedPackets, delta.droppedPackets)
}

func addEntryCounters(entry *TrafficEntry, delta trafficEntryCounters) {
	entry.TXBytes = saturatingAdd(entry.TXBytes, delta.txBytes)
	entry.RXBytes = saturatingAdd(entry.RXBytes, delta.rxBytes)
	entry.TXPackets = saturatingAdd(entry.TXPackets, delta.txPackets)
	entry.RXPackets = saturatingAdd(entry.RXPackets, delta.rxPackets)
}

func setEntryCounters(entry *TrafficEntry, counters trafficEntryCounters) {
	entry.TXBytes = counters.txBytes
	entry.RXBytes = counters.rxBytes
	entry.TXPackets = counters.txPackets
	entry.RXPackets = counters.rxPackets
}

func saturatingAdd(a, b uint64) uint64 {
	if ^uint64(0)-a < b {
		return ^uint64(0)
	}
	return a + b
}

// validMergedTrafficEntry validates the retained, peer-controlled strings in
// a worker snapshot. The control frame is itself bounded, but without field
// limits a worker could rotate near-frame-sized unique strings through pulls
// and make the supervisor retain hundreds of megabytes indefinitely.
func validMergedTrafficEntry(e TrafficEntry) bool {
	return validTrafficText(e.Host, maxTrafficHostBytes, true) &&
		validTrafficText(e.Address, maxTrafficAddressBytes, false) &&
		validTrafficText(e.Protocol, maxTrafficProtocolBytes, false)
}

func validTrafficText(value string, maxBytes int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}

// Snapshot returns a stable in-memory copy, primarily for tests and callers
// that live in the VMM process.
func (r *TrafficRecorder) Snapshot() TrafficSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapshotLocked(time.Now())
}

func (r *TrafficRecorder) ObserveTX(frame []byte, allowed bool) {
	if r == nil || len(frame) == 0 {
		return
	}
	now := time.Now()
	pp, arp, ok := parseFrame(frame)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshot.TXBytes += uint64(len(frame))
	r.snapshot.TXPackets++
	if !allowed {
		r.snapshot.DroppedBytes += uint64(len(frame))
		r.snapshot.DroppedPackets++
	}
	r.dirty = true
	if arp {
		return
	}
	if !ok {
		address, protocol, port := trafficIPv6Endpoint(frame, true)
		if address == "" {
			address, protocol = "non-ipv4", "ether"
		}
		r.recordLocked(address, address, address, protocol, port, allowed, true, len(frame), now)
		return
	}
	if isDHCP(pp.proto, pp.sport, pp.dport) {
		return
	}

	if isDNSRequest(pp) {
		host := dnsQuestionHost(pp)
		if host == "" {
			host = net.IP(pp.dst[:]).String()
		}
		r.recordLocked("dns:"+host, host, net.IP(pp.dst[:]).String(), "dns", 53, allowed, true, len(frame), now)
		return
	}
	address := net.IP(pp.dst[:]).String()
	host := r.hostForLocked(pp.dst, now)
	if host == "" {
		host = address
	}
	r.recordLocked(address, host, address, protocolName(pp.proto), pp.dport, allowed, true, len(frame), now)
}

func (r *TrafficRecorder) ObserveRX(frame []byte) {
	if r == nil || len(frame) == 0 {
		return
	}
	now := time.Now()
	pp, arp, ok := parseFrame(frame)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshot.RXBytes += uint64(len(frame))
	r.snapshot.RXPackets++
	r.dirty = true
	if arp {
		return
	}
	if !ok {
		address, protocol, port := trafficIPv6Endpoint(frame, false)
		if address == "" {
			address, protocol = "non-ipv4", "ether"
		}
		r.recordLocked(address, address, address, protocol, port, true, false, len(frame), now)
		return
	}
	if isDHCP(pp.proto, pp.sport, pp.dport) {
		return
	}

	if pp.srcIsDNS {
		host := r.observeDNSResponseLocked(pp, now)
		if host != "" {
			r.recordLocked("dns:"+host, host, net.IP(pp.src[:]).String(), "dns", 53, true, false, len(frame), now)
			return
		}
	}
	address := net.IP(pp.src[:]).String()
	host := r.hostForLocked(pp.src, now)
	if host == "" {
		host = address
	}
	r.recordLocked(address, host, address, protocolName(pp.proto), pp.sport, true, false, len(frame), now)
}

func (r *TrafficRecorder) recordLocked(keyAddress, host, address, protocol string, port uint16, allowed, tx bool, bytes int, now time.Time) {
	key := trafficEntryKey(keyAddress, host, protocol, port, allowed)
	entry := r.entries[key]
	if entry == nil {
		if len(r.entries) >= maxTrafficEntries {
			return
		}
		entry = &TrafficEntry{
			Host: host, Address: address, Protocol: protocol, Port: port,
			Allowed: allowed, FirstSeen: now,
		}
		r.entries[key] = entry
	} else if host != "" && host != address {
		entry.Host = host
	}
	entry.LastSeen = now
	if tx {
		entry.TXBytes += uint64(bytes)
		entry.TXPackets++
	} else {
		entry.RXBytes += uint64(bytes)
		entry.RXPackets++
	}
}

func trafficEntryKey(address, host, protocol string, port uint16, allowed bool) string {
	// DNS rows are keyed by host because every query goes to the same gateway.
	if protocol == "dns" {
		address = "dns:" + host
	}
	return address + "\x00" + protocol + "\x00" + string(rune(port)) + "\x00" + string(rune(boolByte(allowed)))
}

func boolByte(value bool) byte {
	if value {
		return 1
	}
	return 0
}

func (r *TrafficRecorder) hostForLocked(ip [4]byte, now time.Time) string {
	name, ok := r.dnsNames[ip]
	if !ok {
		return ""
	}
	if now.After(name.expires) {
		delete(r.dnsNames, ip)
		return ""
	}
	return name.host
}

func (r *TrafficRecorder) observeDNSResponseLocked(pp parsedPacket, now time.Time) string {
	payload, _ := dnsPayload(pp)
	if payload == nil {
		return ""
	}
	var message dns.Msg
	if err := message.Unpack(payload); err != nil || !message.Response {
		return ""
	}
	host := ""
	if len(message.Question) > 0 {
		host = normalizeTrafficHost(message.Question[0].Name)
	}
	for _, answer := range message.Answer {
		a, ok := answer.(*dns.A)
		if !ok {
			continue
		}
		v4 := a.A.To4()
		if v4 == nil {
			continue
		}
		answerHost := host
		if answerHost == "" {
			answerHost = normalizeTrafficHost(a.Hdr.Name)
		}
		if answerHost == "" {
			continue
		}
		ttl := time.Duration(a.Hdr.Ttl) * time.Second
		if ttl <= 0 {
			ttl = time.Minute
		}
		if ttl > dnsMaxTTL {
			ttl = dnsMaxTTL
		}
		var key [4]byte
		copy(key[:], v4)
		if _, exists := r.dnsNames[key]; !exists && len(r.dnsNames) >= maxTrafficDNSNames {
			continue
		}
		r.dnsNames[key] = trafficDNSName{host: answerHost, expires: now.Add(ttl)}
	}
	return host
}

func dnsQuestionHost(pp parsedPacket) string {
	payload, _ := dnsPayload(pp)
	if payload == nil {
		return ""
	}
	var message dns.Msg
	if err := message.Unpack(payload); err != nil || message.Response || len(message.Question) == 0 {
		return ""
	}
	return normalizeTrafficHost(message.Question[0].Name)
}

func normalizeTrafficHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if len(host) > 253 {
		return host[:253]
	}
	return host
}

func isDNSRequest(pp parsedPacket) bool {
	return (pp.proto == protoUDP || pp.proto == protoTCP) && pp.dport == 53
}

func isDHCP(proto uint8, sourcePort, destinationPort uint16) bool {
	if proto != protoUDP {
		return false
	}
	return sourcePort == 67 || sourcePort == 68 || destinationPort == 67 || destinationPort == 68
}

func trafficIPv6Endpoint(frame []byte, outbound bool) (address, protocol string, port uint16) {
	if len(frame) < 14+40 || binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv6 || frame[14]>>4 != 6 {
		return "", "", 0
	}
	nextHeader := frame[14+6]
	ip := frame[14+8 : 14+40]
	peer := ip[16:32]
	portOffset := 2
	if !outbound {
		peer = ip[:16]
		portOffset = 0
	}
	protocol = "ipv6"
	switch nextHeader {
	case protoTCP:
		protocol = "tcp6"
	case protoUDP:
		protocol = "udp6"
	case 58:
		protocol = "icmp6"
	}
	if (nextHeader == protoTCP || nextHeader == protoUDP) && len(frame) >= 14+40+4 {
		port = binary.BigEndian.Uint16(frame[14+40+portOffset : 14+40+portOffset+2])
	}
	return net.IP(peer).String(), protocol, port
}

func protocolName(protocol uint8) string {
	switch protocol {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	case protoICMP:
		return "icmp"
	default:
		return "ip"
	}
}

func (r *TrafficRecorder) snapshotLocked(now time.Time) TrafficSnapshot {
	snapshot := r.snapshot
	snapshot.Version = trafficSnapshotVersion
	snapshot.Updated = now
	snapshot.Entries = make([]TrafficEntry, 0, len(r.entries))
	for _, entry := range r.entries {
		snapshot.Entries = append(snapshot.Entries, *entry)
	}
	sort.Slice(snapshot.Entries, func(i, j int) bool {
		return snapshot.Entries[i].LastSeen.After(snapshot.Entries[j].LastSeen)
	})
	return snapshot
}

func (r *TrafficRecorder) flush() {
	r.mu.Lock()
	if !r.dirty {
		r.mu.Unlock()
		return
	}
	snapshot := r.snapshotLocked(time.Now())
	r.dirty = false
	r.mu.Unlock()

	if r.path == "" {
		// In-memory recorder (confined worker): publishing is the
		// supervisor's job via TrafficEpoch; path ops do not exist here.
		return
	}
	data, err := json.Marshal(snapshot)
	if err == nil {
		err = writeTrafficSnapshot(r.path, append(data, '\n'))
	}
	if err != nil {
		r.mu.Lock()
		r.dirty = true
		r.mu.Unlock()
	}
}

func writeTrafficSnapshot(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return atomicfile.WriteFile(path, data, 0o600)
}
