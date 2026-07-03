package tui

import (
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/medunes/misbar/internal/parser"
	"github.com/medunes/misbar/internal/scanner"
	"github.com/medunes/misbar/internal/tailer"
)

// ssRefreshInterval is how often the listening-ports snapshot is re-run.
const ssRefreshInterval = 10 * time.Second

// scanResultMsg carries one artifact's scan result from the scan channel. Its
// handler re-arms waitForScan, so it must only ever be produced by waitForScan.
type scanResultMsg struct{ result scanner.ScanResult }

// periodicResultMsg carries an out-of-band refresh result (e.g. the 10s ss
// tick). Unlike scanResultMsg it does NOT re-arm the scan channel — it is not
// produced by the channel drainer.
type periodicResultMsg struct{ result scanner.ScanResult }

// crossAnomaliesMsg carries the aggregate (cross-artifact) detector results,
// computed once after the static scan completes.
type crossAnomaliesMsg struct{ anomalies []scanner.Anomaly }

// scanDoneMsg signals the scan channel closed — all static scans are complete.
type scanDoneMsg struct{}

// lineMsg carries one tailed log line into the model.
type lineMsg struct{ line tailer.LineMsg }

// liveDoneMsg signals the tailer channel closed (clean live-tail shutdown).
type liveDoneMsg struct{}

// ssTickMsg fires every ssRefreshInterval to re-run `ss -tulnp`.
type ssTickMsg struct{}

// lineEntry is one buffered live line with its severity classification.
type lineEntry struct {
	text string
	sev  parser.Severity
}

// waitForScan drains one result from ch and, via the handler re-arming it, forms
// a single self-rescheduling Cmd that owns the channel. A closed channel yields
// scanDoneMsg; the ok==false guard is mandatory or it would spin forever
// re-arming on a closed channel.
func waitForScan(ch <-chan scanner.ScanResult) tea.Cmd {
	return func() tea.Msg {
		r, ok := <-ch
		if !ok {
			return scanDoneMsg{}
		}
		return scanResultMsg{r}
	}
}

// waitForLine is the tailer analogue of waitForScan: one self-rescheduling Cmd
// draining the shared line channel. A closed channel yields liveDoneMsg.
func waitForLine(ch <-chan tailer.LineMsg) tea.Cmd {
	return func() tea.Msg {
		l, ok := <-ch
		if !ok {
			return liveDoneMsg{}
		}
		return lineMsg{l}
	}
}

// tickSS schedules the next periodic ss refresh.
func tickSS() tea.Cmd {
	return tea.Tick(ssRefreshInterval, func(time.Time) tea.Msg { return ssTickMsg{} })
}
