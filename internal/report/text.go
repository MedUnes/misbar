package report

import (
	"fmt"
	"io"
	"strings"
)

// WriteText writes a human-readable report. Without verbose, only flagged
// (WARN/CRIT/locked) artifacts are listed; verbose lists every artifact.
func WriteText(w io.Writer, rep Report, verbose bool) error {
	var b strings.Builder

	fmt.Fprintf(&b, "misbar — %s [%s]", rep.Host, rep.Access)
	if rep.Generated != "" {
		fmt.Fprintf(&b, ", %s", rep.Generated)
	}
	b.WriteByte('\n')
	fmt.Fprintf(&b, "distro %s · crit %d · warn %d · ok %d · skip %d\n",
		rep.Distro, rep.Counts.Crit, rep.Counts.Warn, rep.Counts.OK, rep.Counts.Skip)

	for _, cat := range rep.Categories {
		fmt.Fprintf(&b, "\n[%d] %s — %s\n", cat.ID, cat.Label, cat.Health)
		for _, a := range cat.Artifacts {
			flagged := a.Health == "WARN" || a.Health == "CRIT" || a.Locked
			if !verbose && !flagged {
				continue
			}
			lock := ""
			if a.Locked {
				lock = " 🔒"
			}
			fmt.Fprintf(&b, "  %-4s %-16s %s%s\n", a.Health, a.ID, a.Summary, lock)
			for _, an := range a.Anomalies {
				fmt.Fprintf(&b, "       ! %s\n", an.Title)
			}
		}
	}

	if len(rep.Aggregate) > 0 {
		b.WriteString("\nAggregate anomalies:\n")
		for _, an := range rep.Aggregate {
			fmt.Fprintf(&b, "  ! [%s] %s\n", an.Severity, an.Title)
			if an.Detail != "" {
				fmt.Fprintf(&b, "        %s\n", an.Detail)
			}
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}
