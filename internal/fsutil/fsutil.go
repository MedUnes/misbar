// Package fsutil provides bounded, root-agnostic filesystem primitives that
// scanners reach through Env. It does the IO; Env composes the root prefix and
// scanner.Classify maps the returned errors to a Health.
package fsutil

import (
	"bytes"
	"io"
	"os"
)

// ReadFileBounded reads up to maxBytes from path. It returns the content, a
// truncated flag (the file was longer than maxBytes), and any error. The error
// is returned verbatim so callers can distinguish os.ErrNotExist from
// os.ErrPermission.
func ReadFileBounded(path string, maxBytes int) (data []byte, truncated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	// Read one extra byte so we can tell a file that exactly fills the budget
	// apart from one that overflows it.
	buf, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, false, err
	}
	if len(buf) > maxBytes {
		return buf[:maxBytes], true, nil
	}
	return buf, false, nil
}

// ReadFileTail returns the last maxBytes of a file — the right window for logs,
// where recent lines matter. When truncated, the leading partial line is
// dropped so callers only see whole lines.
func ReadFileTail(path string, maxBytes int) (data []byte, truncated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if info.Size() <= int64(maxBytes) {
		b, err := io.ReadAll(f)
		return b, false, err
	}
	if _, err := f.Seek(info.Size()-int64(maxBytes), io.SeekStart); err != nil {
		return nil, false, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, false, err
	}
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[i+1:] // drop the partial first line
	}
	return b, true, nil
}

// FileExists reports whether path exists and is stat-able.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// StatInfo returns os.Stat for mtime/ctime "recently modified" checks.
func StatInfo(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// ListDir lists the immediate entries of a directory.
func ListDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}
