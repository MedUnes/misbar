package parser

import "testing"

func TestClassifyLine(t *testing.T) {
	cases := []struct {
		line string
		want Severity
	}{
		{"Jan  1 00:00:00 host kernel: Kernel panic - not syncing", SevEmerg},
		{"host kernel: segfault at 0 ip 00007f", SevCrit},
		{"Out of memory: Killed process 1234", SevCrit},
		{"sshd[1]: error: connection reset", SevErr},
		{"pam_unix: authentication failure for root", SevErr},
		{"systemd: WARNING: unit is masked", SevWarning},
		{"cron: notice: reloaded configuration", SevNotice},
		{"app: debug: entering handler", SevDebug},
		{"sshd: Accepted publickey for admin", SevInfo},
	}
	for _, c := range cases {
		if got := ClassifyLine(c.line); got != c.want {
			t.Errorf("ClassifyLine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestSeverityBands(t *testing.T) {
	if !SevErr.IsError() || !SevCrit.IsError() || !SevEmerg.IsError() {
		t.Error("emerg/crit/err should be in the error band")
	}
	if SevWarning.IsError() || SevInfo.IsError() {
		t.Error("warning/info should not be in the error band")
	}
	if !SevWarning.IsWarning() || SevErr.IsWarning() {
		t.Error("IsWarning should match only the warning level")
	}
}
