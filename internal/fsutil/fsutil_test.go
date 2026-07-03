package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileBounded(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}

	data, trunc, err := ReadFileBounded(p, 100)
	if err != nil || trunc || string(data) != "hello world" {
		t.Errorf("within budget: data=%q trunc=%v err=%v", data, trunc, err)
	}

	data, trunc, err = ReadFileBounded(p, 5)
	if err != nil || !trunc || string(data) != "hello" {
		t.Errorf("over budget: data=%q trunc=%v err=%v", data, trunc, err)
	}

	if _, _, err := ReadFileBounded(filepath.Join(dir, "missing"), 10); !os.IsNotExist(err) {
		t.Errorf("missing file err = %v, want ErrNotExist", err)
	}
}

func TestReadFileTail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.WriteFile(p, []byte("line1\nline2\nline3\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	data, trunc, err := ReadFileTail(p, 100)
	if err != nil || trunc || string(data) != "line1\nline2\nline3\n" {
		t.Errorf("full tail: data=%q trunc=%v err=%v", data, trunc, err)
	}

	// Last 10 bytes span a partial line; the leading partial must be dropped.
	data, trunc, err = ReadFileTail(p, 10)
	if err != nil || !trunc {
		t.Fatalf("tail: trunc=%v err=%v", trunc, err)
	}
	if string(data) != "line3\n" {
		t.Errorf("tail dropped partial line wrong: got %q, want %q", data, "line3\n")
	}
}

func TestFileExistsStatListDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	if FileExists(p) {
		t.Error("FileExists on a missing file should be false")
	}
	if err := os.WriteFile(p, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !FileExists(p) {
		t.Error("FileExists on an existing file should be true")
	}
	if info, err := StatInfo(p); err != nil || info.Size() != 2 {
		t.Errorf("StatInfo: err=%v size=%d", err, safeSize(info))
	}
	entries, err := ListDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("ListDir: err=%v entries=%d", err, len(entries))
	}
}

func safeSize(info os.FileInfo) int64 {
	if info == nil {
		return -1
	}
	return info.Size()
}
