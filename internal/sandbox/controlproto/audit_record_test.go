package controlproto

import (
	"testing"
	"time"
)

func TestAuditRecordsRoundTripAndAcceptLegacyLines(t *testing.T) {
	at := time.Date(2026, 9, 22, 9, 42, 17, 123456789, time.FixedZone("CEST", 2*3600))
	// Sanitized events never contain a raw TAB; an escaped one stays literal.
	line := `policy: {"reason":"a\tb"}`
	record := FormatAuditRecord(at, line)
	if record != "2026-09-22T07:42:17.123456789Z\t"+line {
		t.Fatalf("record = %q", record)
	}
	gotAt, gotLine := ParseAuditRecord(record)
	if !gotAt.Equal(at) || gotLine != line {
		t.Fatalf("parsed %v %q", gotAt, gotLine)
	}
	for _, legacy := range []string{"mcp: session open", "not-a-time\tsuffix", ""} {
		gotAt, gotLine := ParseAuditRecord(legacy)
		if !gotAt.IsZero() || gotLine != legacy {
			t.Fatalf("legacy %q parsed as %v %q", legacy, gotAt, gotLine)
		}
	}
}
