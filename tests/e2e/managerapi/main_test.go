package main

import (
	"bufio"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadEventSkipsCommentsAndParsesData(t *testing.T) {
	input := ": connected\n\nid: 7\nevent: operation\ndata: {\"id\":7,\"type\":\"operation\",\"operationId\":\"abc\",\"state\":\"succeeded\"}\n\n"
	got, err := readEvent(bufio.NewReader(strings.NewReader(input)))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 7 || got.Type != "operation" || got.OperationID != "abc" || got.State != "succeeded" {
		t.Fatalf("event = %+v", got)
	}
}

func TestCheckSocketPathBudgetRejectsLongWorkspace(t *testing.T) {
	path := filepath.Join(string(filepath.Separator), strings.Repeat("long", 40))
	if err := checkSocketPathBudget(path, "manager-e2e"); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("checkSocketPathBudget(%q) = %v, want path-too-long error", path, err)
	}
}
