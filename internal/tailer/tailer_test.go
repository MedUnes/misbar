package tailer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/medunes/misbar/internal/parser"
)

func TestDecide(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	write := func(s string) os.FileInfo {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi
	}

	prev := write("one\n")
	grew := write("one\ntwo\n")
	if got := decide(prev, grew); got != actContinue {
		t.Errorf("grew → %v, want continue", got)
	}
	shrank := write("x\n")
	if got := decide(grew, shrank); got != actRewind {
		t.Errorf("shrank → %v, want rewind", got)
	}

	// A different file (different inode) means the log rotated → reopen.
	p2 := filepath.Join(dir, "log2")
	if err := os.WriteFile(p2, []byte("z\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other, _ := os.Stat(p2)
	if got := decide(shrank, other); got != actReopen {
		t.Errorf("rotated → %v, want reopen", got)
	}

	if decide(nil, other) != actContinue {
		t.Error("nil prev should be continue")
	}
}

func TestDrain(t *testing.T) {
	collect := func(r string, carry string) ([]string, string) {
		var got []string
		out, err := drain(strings.NewReader(r), carry, func(s string) { got = append(got, s) })
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
		return got, out
	}

	got, carry := collect("line1\nline2\n", "")
	if len(got) != 2 || got[0] != "line1" || got[1] != "line2" || carry != "" {
		t.Errorf("two lines: got=%v carry=%q", got, carry)
	}

	got, carry = collect("partial", "")
	if len(got) != 0 || carry != "partial" {
		t.Errorf("partial: got=%v carry=%q", got, carry)
	}

	got, carry = collect("fix\ndone\n", "pre")
	if len(got) != 2 || got[0] != "prefix" || got[1] != "done" || carry != "" {
		t.Errorf("carry join: got=%v carry=%q", got, carry)
	}

	got, _ = collect("a\r\nb\r\n", "")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("CRLF trim: got=%v", got)
	}
}

func TestManagerTailsAppendsThenClosesOnCancel(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	if err := os.WriteFile(p, []byte("snapshot line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := NewManager()
	m.Start(ctx, []Source{{ID: "app", Path: p}})

	time.Sleep(200 * time.Millisecond) // let the tailer open and seek to EOF

	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("brand new ERROR line\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	select {
	case msg := <-m.Lines():
		if msg.Line != "brand new ERROR line" {
			t.Errorf("line = %q", msg.Line)
		}
		if msg.Sev != parser.SevErr {
			t.Errorf("severity = %v, want ERR", msg.Sev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no tailed line within 5s")
	}

	// Cancelling must close the channel — proving watchers/goroutines shut down.
	cancel()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-m.Lines():
			if !ok {
				return // clean close
			}
		case <-deadline:
			t.Fatal("channel not closed after cancel")
		}
	}
}
