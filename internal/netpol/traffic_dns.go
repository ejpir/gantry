package netpol

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

type trafficDNSName struct {
	host    string
	expires time.Time
}

// trafficDNSCache gives the bounded address-to-host map a domain owner instead
// of exposing map mutation to the traffic aggregate.
type trafficDNSCache struct {
	names map[[4]byte]trafficDNSName
}

func newTrafficDNSCache() trafficDNSCache {
	return trafficDNSCache{names: make(map[[4]byte]trafficDNSName)}
}

func (cache *trafficDNSCache) lookup(ip [4]byte, now time.Time) string {
	name, ok := cache.names[ip]
	if !ok {
		return ""
	}
	if now.After(name.expires) {
		delete(cache.names, ip)
		return ""
	}
	return name.host
}

func (cache *trafficDNSCache) observeResponse(packet parsedPacket, now time.Time) string {
	message, ok := unpackDNSMessage(packet)
	if !ok || !message.Response {
		return ""
	}
	host := dnsResponseHost(message)
	for _, answer := range message.Answer {
		record, ok := answer.(*dns.A)
		if ok {
			cache.rememberARecord(record, host, now)
		}
	}
	return host
}

func (cache *trafficDNSCache) rememberARecord(record *dns.A, questionHost string, now time.Time) {
	address := record.A.To4()
	if address == nil {
		return
	}
	host := questionHost
	if host == "" {
		host = normalizeTrafficHost(record.Hdr.Name)
	}
	if host == "" {
		return
	}
	var key [4]byte
	copy(key[:], address)
	if _, exists := cache.names[key]; !exists && len(cache.names) >= maxTrafficDNSNames {
		return
	}
	cache.names[key] = trafficDNSName{host: host, expires: now.Add(boundedDNSTTL(record.Hdr.Ttl))}
}

func boundedDNSTTL(seconds uint32) time.Duration {
	ttl := time.Duration(seconds) * time.Second
	if ttl <= 0 {
		return time.Minute
	}
	if ttl > dnsMaxTTL {
		return dnsMaxTTL
	}
	return ttl
}

func dnsResponseHost(message *dns.Msg) string {
	if len(message.Question) == 0 {
		return ""
	}
	return normalizeTrafficHost(message.Question[0].Name)
}

func dnsQuestionHost(packet parsedPacket) string {
	message, ok := unpackDNSMessage(packet)
	if !ok || message.Response || len(message.Question) == 0 {
		return ""
	}
	return normalizeTrafficHost(message.Question[0].Name)
}

func unpackDNSMessage(packet parsedPacket) (*dns.Msg, bool) {
	payload, _ := dnsPayload(packet)
	if payload == nil {
		return nil, false
	}
	message := new(dns.Msg)
	if err := message.Unpack(payload); err != nil {
		return nil, false
	}
	return message, true
}

func normalizeTrafficHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if len(host) > maxTrafficHostBytes {
		return host[:maxTrafficHostBytes]
	}
	return host
}
