package config

import "testing"

func TestParsePortSpec(t *testing.T) {
	cases := []struct {
		in      string
		want    PortMapping
		wantErr bool
	}{
		{in: "8080:80", want: PortMapping{HostIP: "127.0.0.1", HostPort: 8080, GuestPort: 80, Proto: "tcp"}},
		{in: "127.0.0.1:8080:80", want: PortMapping{HostIP: "127.0.0.1", HostPort: 8080, GuestPort: 80, Proto: "tcp"}},
		{in: "0.0.0.0:8080:80/udp", want: PortMapping{HostIP: "0.0.0.0", HostPort: 8080, GuestPort: 80, Proto: "udp"}},
		{in: "[::1]:8080:80", want: PortMapping{HostIP: "::1", HostPort: 8080, GuestPort: 80, Proto: "tcp"}},
		{in: "80", want: PortMapping{HostIP: "127.0.0.1", HostPort: 0, GuestPort: 80, Proto: "tcp"}},
		{in: "0:80", want: PortMapping{HostIP: "127.0.0.1", HostPort: 0, GuestPort: 80, Proto: "tcp"}},
		{in: "5353:53/UDP", want: PortMapping{HostIP: "127.0.0.1", HostPort: 5353, GuestPort: 53, Proto: "udp"}},
		{in: "", wantErr: true},
		{in: "abc:80", wantErr: true},          // non-numeric host port
		{in: "8080:0", wantErr: true},          // no guest port
		{in: "8080:80/sctp", wantErr: true},    // unsupported protocol
		{in: "1.2.3.4.5:80:80", wantErr: true}, // bad bind address
		{in: ":8080:80", wantErr: true},        // empty IP must be written explicitly
		{in: "1:2:3:4", wantErr: true},
	}
	for _, tc := range cases {
		got, err := ParsePortSpec(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePortSpec(%q) = %+v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortSpec(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParsePortSpec(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
		if round, err := ParsePortSpec(got.String()); err != nil || round != got {
			t.Errorf("String() round-trip %q: %+v / %v", tc.in, round, err)
		}
	}
}

// Single-part form is Docker's "random host port": guest port only.
func TestParsePortSpecSinglePart(t *testing.T) {
	m, err := ParsePortSpec("8080")
	if err != nil {
		t.Fatal(err)
	}
	if m.HostPort != 0 || m.GuestPort != 8080 {
		t.Fatalf("single-part spec: %+v, want auto host port + guest 8080", m)
	}
}

func TestNormalizePortSpecAssignsHostPort(t *testing.T) {
	got, err := NormalizePortSpec("80")
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParsePortSpec(got)
	if err != nil {
		t.Fatal(err)
	}
	if m.HostPort == 0 {
		t.Fatalf("normalize %q left host port at 0", got)
	}
	if m.GuestPort != 80 || m.Proto != "tcp" || m.HostIP != "127.0.0.1" {
		t.Fatalf("normalize %q mangled the mapping: %+v", got, m)
	}
	udp, err := NormalizePortSpec("5353:53/udp")
	if err != nil {
		t.Fatal(err)
	}
	um, _ := ParsePortSpec(udp)
	if um.HostPort != 5353 || um.Proto != "udp" {
		t.Fatalf("udp normalize: %+v", um)
	}
}

func TestPortMappingShort(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:8080:80":     "8080→80",
		"0.0.0.0:8080:80":       "0.0.0.0:8080→80",
		"127.0.0.1:5353:53/udp": "5353→53/udp",
	}
	for in, want := range cases {
		m, err := ParsePortSpec(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := m.Short(); got != want {
			t.Errorf("Short(%q) = %q, want %q", in, got, want)
		}
	}
}
