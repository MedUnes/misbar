// Package tailer streams new lines from live log files. It watches each file and
// its parent directory with fsnotify, backed by a periodic re-stat as a safety
// net, and handles rotation (inode change) and truncation (copytruncate). Lines
// flow out one shared channel; the TUI stores them in bounded per-source rings.
package tailer

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/medunes/misbar/internal/parser"
)

const (
	maxLineBytes = 64 * 1024       // cap a single line so a firehose can't OOM
	maxReadBytes = 8 * 1024 * 1024 // cap one drain pass
	pollInterval = 2 * time.Second // re-stat safety net for coalesced events
)

// SourceID identifies a tailed source (the artifact's ID).
type SourceID string

// LineMsg is one new line from a tailed source, pre-classified by severity.
type LineMsg struct {
	Src  SourceID
	Line string
	Sev  parser.Severity
}

// Source is a file to tail.
type Source struct {
	ID   SourceID
	Path string
}

// action is what a tailer must do before reading, given how the file changed.
type action uint8

const (
	actContinue action = iota // same file, read newly-appended bytes
	actReopen                 // inode changed (rotated) — reopen from the start
	actRewind                 // file shrank (copytruncate) — seek back to 0
)

// decide is the pure rotation/truncation decision, unit-testable without
// fsnotify. A missing prev or cur is treated as "continue".
func decide(prev, cur os.FileInfo) action {
	if prev == nil || cur == nil {
		return actContinue
	}
	if !os.SameFile(prev, cur) {
		return actReopen
	}
	if cur.Size() < prev.Size() {
		return actRewind
	}
	return actContinue
}

// drain reads all currently-available bytes from r, prepends carry, emits every
// complete line, and returns the trailing partial line as the next carry. Lines
// are trimmed of a trailing CR and truncated to maxLineBytes.
func drain(r io.Reader, carry string, emit func(string)) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxReadBytes))
	buf := carry + string(data)
	for {
		i := strings.IndexByte(buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(buf[:i], "\r")
		if len(line) > maxLineBytes {
			line = line[:maxLineBytes]
		}
		emit(line)
		buf = buf[i+1:]
	}
	// Cap the trailing partial line so a newline-less firehose can't grow the
	// carry without bound across drains.
	if len(buf) > maxLineBytes {
		buf = buf[:maxLineBytes]
	}
	return buf, err
}

// Manager tails a set of sources until its context is cancelled.
type Manager struct {
	out chan LineMsg
}

// NewManager creates a manager with a buffered output channel.
func NewManager() *Manager {
	return &Manager{out: make(chan LineMsg, 256)}
}

// Lines is the shared output channel. It is closed once every tailer stops
// (after ctx is cancelled), signalling a clean shutdown.
func (m *Manager) Lines() <-chan LineMsg { return m.out }

// Start launches a goroutine per source and a closer that shuts the output
// channel when they all finish. It returns immediately.
func (m *Manager) Start(ctx context.Context, sources []Source) {
	var wg sync.WaitGroup
	for _, src := range sources {
		wg.Go(func() { m.tail(ctx, src) })
	}
	go func() {
		wg.Wait()
		close(m.out)
	}()
}

// emit sends a line unless the context is done.
func (m *Manager) emit(ctx context.Context, msg LineMsg) {
	select {
	case m.out <- msg:
	case <-ctx.Done():
	}
}

// tail streams one file. It seeks to EOF (the static scan already captured the
// snapshot), then reads on every fsnotify event and every poll tick, handling
// rotation via decide.
func (m *Manager) tail(ctx context.Context, src Source) {
	f, err := os.Open(src.Path)
	if err != nil {
		// The file may not exist yet; the poll loop will pick it up on Create.
		f = nil
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	var prev os.FileInfo
	if f != nil {
		if _, serr := f.Seek(0, io.SeekEnd); serr == nil {
			prev, _ = f.Stat()
		}
	}

	var events chan fsnotify.Event
	if w, werr := fsnotify.NewWatcher(); werr == nil {
		defer w.Close()
		_ = w.Add(filepath.Dir(src.Path))
		if f != nil {
			_ = w.Add(src.Path)
		}
		events = make(chan fsnotify.Event, 1)
		go forward(ctx, w, events)
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	carry := ""
	readNew := func() {
		cur, serr := os.Stat(src.Path)
		if serr != nil {
			return // file gone for now; keep waiting
		}
		switch {
		case f == nil: // file (re)appeared
			if nf, oerr := os.Open(src.Path); oerr == nil {
				f, carry = nf, ""
			}
		case decide(prev, cur) == actReopen:
			f.Close()
			if nf, oerr := os.Open(src.Path); oerr == nil {
				f, carry = nf, ""
			}
		case decide(prev, cur) == actRewind:
			_, _ = f.Seek(0, io.SeekStart)
			carry = ""
		}
		prev = cur
		if f == nil {
			return
		}
		carry, _ = drain(f, carry, func(line string) {
			m.emit(ctx, LineMsg{Src: src.ID, Line: line, Sev: parser.ClassifyLine(line)})
		})
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-events:
			readNew()
		case <-ticker.C:
			readNew()
		}
	}
}

// forward relays watcher events into ch until ctx is cancelled, so the tail loop
// can select on a plain channel and always honour cancellation.
func forward(ctx context.Context, w *fsnotify.Watcher, ch chan<- fsnotify.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			select {
			case ch <- ev:
			case <-ctx.Done():
				return
			default: // coalesce: the poll tick will still catch up
			}
		case <-w.Errors:
		}
	}
}
