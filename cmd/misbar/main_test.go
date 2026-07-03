package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// stubLaunch records whether the launcher was invoked and returns err.
func stubLaunch(called *bool, err error) func(config) error {
	return func(config) error {
		*called = true
		return err
	}
}

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		launchErr  error
		wantCode   int
		wantStdout string
		wantStderr string
		wantLaunch bool
	}{
		{name: "version", args: []string{"--version"}, wantCode: 0, wantStdout: "misbar"},
		{name: "help", args: []string{"--help"}, wantCode: 0, wantStderr: "Usage"},
		{name: "unknown flag", args: []string{"--nope"}, wantCode: 2, wantStderr: "not defined"},
		{name: "no args launches TUI", args: nil, wantCode: 0, wantLaunch: true},
		{name: "launch failure", args: nil, launchErr: errors.New("boom"), wantCode: 1, wantStderr: "boom", wantLaunch: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			var launched bool
			code := run(tt.args, &stdout, &stderr, stubLaunch(&launched, tt.launchErr))

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if launched != tt.wantLaunch {
				t.Errorf("launched = %v, want %v", launched, tt.wantLaunch)
			}
			if tt.wantStdout != "" && !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestBuildVersion(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = "v1.2.3"
	if got := buildVersion(); got != "v1.2.3" {
		t.Errorf("buildVersion() = %q, want %q", got, "v1.2.3")
	}
	version = ""
	if got := buildVersion(); got == "" {
		t.Error("buildVersion() returned empty string, want a fallback")
	}
}
