package tui

import (
	"context"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/medunes/misbar/internal/parser"
	"github.com/medunes/misbar/internal/scanner"
	"github.com/medunes/misbar/internal/scanner/categories"
	"github.com/medunes/misbar/internal/tailer"
)

// testApp builds an App over a real orchestrator rooted at an empty temp dir, so
// New's skeleton build works without touching the live system.
func testApp(t *testing.T) *App {
	t.Helper()
	env := scanner.NewEnv(t.TempDir(), time.Hour)
	a := New(scanner.NewOrchestrator(env, categories.All()...))
	a.noLive = true // unit tests are static-only; live tailing has its own tests
	return a
}

// press builds a printable-key press message (e.g. "1", "h").
func press(s string) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: []rune(s)[0], Text: s}
}

func TestNumberKeyEntersDrilldown(t *testing.T) {
	a := testApp(t)
	a.Update(press("5")) // Persistence is grid slot 5
	if a.mode != modeDrilldown {
		t.Fatalf("mode = %d, want drilldown", a.mode)
	}
	if a.focusCat != 4 {
		t.Errorf("focusCat = %d, want 4", a.focusCat)
	}
	if a.drill.cat.meta.ID != scanner.CatPersistence {
		t.Errorf("drill category = %v, want Persistence", a.drill.cat.meta.ID)
	}
	// Out-of-range digits are ignored.
	a.Update(press("9"))
	if a.focusCat != 4 {
		t.Errorf("key 9 changed focus to %d, want 4", a.focusCat)
	}
}

func TestTabCyclesOverviewFocus(t *testing.T) {
	a := testApp(t)
	a.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	if a.mode != modeOverview || a.focusCat != 1 {
		t.Fatalf("tab → mode %d focus %d, want overview 1", a.mode, a.focusCat)
	}
	a.Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}) // back to 0
	a.Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}) // wrap to 5
	if a.focusCat != 5 {
		t.Errorf("shift+tab wrap → %d, want 5", a.focusCat)
	}
}

func TestGridMove(t *testing.T) {
	a := testApp(t)
	steps := []struct {
		dRow, dCol, want int
	}{
		{0, 1, 1}, {1, 0, 4}, {0, -1, 3}, {-1, 0, 0}, {0, -1, 2}, {-1, 0, 5},
	}
	for _, s := range steps {
		a.moveFocus(s.dRow, s.dCol)
		if a.focusCat != s.want {
			t.Errorf("moveFocus(%d,%d) → %d, want %d", s.dRow, s.dCol, a.focusCat, s.want)
		}
	}
}

func TestEscReturnsToOverview(t *testing.T) {
	a := testApp(t)
	a.Update(press("3"))
	if a.mode != modeDrilldown {
		t.Fatal("expected drilldown after number key")
	}
	a.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if a.mode != modeOverview {
		t.Errorf("esc → mode %d, want overview", a.mode)
	}
}

func TestDrilldownListNavClamps(t *testing.T) {
	a := testApp(t)
	a.Update(press("5")) // Persistence has many artifacts
	n := len(a.drill.cat.rows)
	if n == 0 {
		t.Fatal("Persistence should have artifact rows")
	}
	// Up at the top stays at 0.
	a.Update(tea.KeyPressMsg{Code: tea.KeyUp})
	if a.drill.sel != 0 {
		t.Errorf("up at top → sel %d, want 0", a.drill.sel)
	}
	// Down past the end clamps to the last row.
	for range n + 5 {
		a.Update(press("j"))
	}
	if a.drill.sel != n-1 {
		t.Errorf("down past end → sel %d, want %d", a.drill.sel, n-1)
	}
}

func TestScanResultFlow(t *testing.T) {
	a := testApp(t)
	// A crit result for ld.so.preload should roll into the Persistence slot.
	r := scanner.ScanResult{
		Category: scanner.CatPersistence,
		Artifact: "ld.so.preload",
		Health:   scanner.HealthCrit,
		Summary:  "NON-EMPTY",
		Anomalies: []scanner.Anomaly{
			{Severity: scanner.HealthCrit, Title: "ld.so.preload is non-empty", Artifact: "ld.so.preload"},
		},
	}
	_, cmd := a.Update(scanResultMsg{result: r})
	if cmd == nil {
		t.Error("scanResultMsg should re-arm waitForScan (non-nil cmd)")
	}
	idx := a.catIndex[scanner.CatPersistence]
	if got := a.cats[idx].health(); got != scanner.HealthCrit {
		t.Errorf("Persistence health = %v, want CRIT", got)
	}
	// scanDone stops the scanning flag.
	a.Update(scanDoneMsg{})
	if a.scanning {
		t.Error("scanning should be false after scanDoneMsg")
	}
}

func TestLiveLineBufferBounded(t *testing.T) {
	a := testApp(t)

	// A line delivered via Update lands in the right source buffer, classified.
	a.Update(lineMsg{line: tailer.LineMsg{Src: "syslog", Line: "ERROR boom", Sev: parser.SevErr}})
	got := a.lines["syslog"]
	if len(got) != 1 || got[0].text != "ERROR boom" || got[0].sev != parser.SevErr {
		t.Fatalf("buffered line = %+v", got)
	}

	// The ring buffer never grows past ringCap.
	for range ringCap + 50 {
		a.appendLine(tailer.LineMsg{Src: "syslog", Line: "x", Sev: parser.SevInfo})
	}
	if n := len(a.lines["syslog"]); n != ringCap {
		t.Errorf("ring size = %d, want %d", n, ringCap)
	}
}

func TestHelpOverlayToggles(t *testing.T) {
	a := testApp(t)
	a.Update(press("?"))
	if a.overlay != overlayHelp {
		t.Fatal("? should open the help overlay")
	}
	a.Update(press("?"))
	if a.overlay != overlayNone {
		t.Error("? should close the help overlay")
	}
}

func TestRescanClearsResults(t *testing.T) {
	a := testApp(t)
	a.Update(scanResultMsg{result: scanner.ScanResult{
		Category: scanner.CatPersistence, Artifact: "ld.so.preload", Health: scanner.HealthCrit,
	}})
	a.Update(scanDoneMsg{})
	idx := a.catIndex[scanner.CatPersistence]
	if a.cats[idx].scanned() == 0 {
		t.Fatal("expected a result before rescan")
	}

	cmd := a.rescan()
	if a.cats[idx].scanned() != 0 {
		t.Error("rescan should clear results immediately")
	}
	if !a.scanning {
		t.Error("rescan should set scanning=true")
	}
	// Drain the fresh scan so its worker goroutines don't leak.
	for cmd != nil {
		switch m := cmd().(type) {
		case scanResultMsg:
			a.applyResult(m.result)
			cmd = waitForScan(a.scanCh)
		default:
			cmd = nil
		}
	}
}

func TestFullscreenSearch(t *testing.T) {
	a := testApp(t)
	r := scanner.ScanResult{
		Artifact: "syslog",
		Content:  scanner.Content{Text: "line one\nERROR two\nline three\nERROR four\n"},
	}
	a.full = newFullscreen(a.styles, "syslog", r)
	a.full.resize(80, 20)
	a.mode = modeFullscreen

	if got := a.full.find("error"); len(got) != 2 {
		t.Fatalf("find(error) = %v, want 2 matches", got)
	}

	// Type a query and commit it through the input handler.
	a.search = searchState{inputting: true}
	for _, c := range "error" {
		a.handleSearchInput(tea.KeyPressMsg{Code: c, Text: string(c)})
	}
	a.commitSearch()
	if len(a.search.matches) != 2 {
		t.Fatalf("committed matches = %d, want 2", len(a.search.matches))
	}
	a.cycleMatch(1)
	if a.search.idx != 1 {
		t.Errorf("after next, idx = %d, want 1", a.search.idx)
	}
	a.cycleMatch(1) // wraps
	if a.search.idx != 0 {
		t.Errorf("after wrap, idx = %d, want 0", a.search.idx)
	}
}

func TestYankReturnsClipboardCmd(t *testing.T) {
	a := testApp(t)
	r := scanner.ScanResult{Artifact: "x", Content: scanner.Content{Text: "alpha\nbeta\n"}}
	a.full = newFullscreen(a.styles, "x", r)
	a.full.resize(80, 20)
	a.mode = modeFullscreen

	if _, cmd := a.Update(press("y")); cmd == nil {
		t.Error("y should return a SetClipboard command")
	}
}

func TestSearchInputCapturesQNotQuit(t *testing.T) {
	a := testApp(t)
	a.full = newFullscreen(a.styles, "x", scanner.ScanResult{
		Artifact: "x", Content: scanner.Content{Text: "query\nrequest\n"},
	})
	a.full.resize(80, 20)
	a.mode = modeFullscreen

	a.Update(press("/")) // open search
	if !a.search.inputting {
		t.Fatal("/ should start search input")
	}
	// A literal 'q' must be typed into the query, NOT quit the program.
	if _, cmd := a.Update(press("q")); cmd != nil {
		t.Error("typing 'q' in a search returned a command (quit?), want nil")
	}
	if a.search.query != "q" {
		t.Errorf("query = %q, want %q", a.search.query, "q")
	}
	// ctrl+c still force-quits from the search prompt.
	if _, cmd := a.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}); cmd == nil {
		t.Error("ctrl+c should quit even while searching")
	}
}

func TestPeriodicResultDoesNotReArm(t *testing.T) {
	a := testApp(t)
	// The out-of-band ss refresh must apply its result WITHOUT returning a
	// re-arm command (re-arming the closed scan channel is the OOM bug).
	_, cmd := a.Update(periodicResultMsg{result: scanner.ScanResult{
		Category: scanner.CatNetwork, Artifact: "listening-ports", Health: scanner.HealthOK, Summary: "5 listening ports",
	}})
	if cmd != nil {
		t.Error("periodicResultMsg must not return a command")
	}
	if _, ok := a.cats[a.catIndex[scanner.CatNetwork]].result("listening-ports"); !ok {
		t.Error("periodic result was not applied")
	}
}

func TestStartLiveRunsOnlyOnce(t *testing.T) {
	a := testApp(t)
	a.noLive = false
	ctx, cancel := context.WithCancel(context.Background())
	a.ctx, a.cancel = ctx, cancel
	t.Cleanup(cancel) // stop tailer goroutines when the test ends

	a.Update(scanDoneMsg{})
	first := a.tailMgr
	if !a.liveStarted || first == nil {
		t.Fatal("first scanDone should start live tailing")
	}
	// A rescan's scanDone must NOT create a second manager (goroutine/FD leak).
	a.Update(scanDoneMsg{})
	if a.tailMgr != first {
		t.Error("second scanDone re-created the tailer manager")
	}
}

func TestAggregateAnomaliesSurfaceInTUI(t *testing.T) {
	a := testApp(t)
	a.Update(crossAnomaliesMsg{anomalies: []scanner.Anomaly{
		{Severity: scanner.HealthCrit, Title: "brute force: 8 failed logins from 1.2.3.4", Artifact: "btmp"},
	}})
	cs := a.cats[a.catIndex[scanner.CatAuthUsers]]
	if cs.health() != scanner.HealthCrit {
		t.Errorf("Auth health = %v, want CRIT from the aggregate anomaly", cs.health())
	}
	if top := cs.topAnomaly(); top == nil || top.Title != "brute force: 8 failed logins from 1.2.3.4" {
		t.Errorf("topAnomaly = %+v, want the brute-force anomaly", top)
	}
	// Re-applying replaces rather than accumulates.
	a.Update(crossAnomaliesMsg{anomalies: nil})
	if len(cs.aggregate) != 0 {
		t.Error("aggregate anomalies should be replaced (cleared) on re-apply")
	}
}

func TestSummaryReportsDeniedNotOK(t *testing.T) {
	cs := newCategoryState(scanner.CategoryMeta{ID: scanner.CatAuthUsers, Label: "Auth & Users"})
	cs.hasScanner = true
	cs.apply(scanner.ScanResult{Artifact: "passwd", Health: scanner.HealthOK})
	cs.apply(scanner.ScanResult{Artifact: "shadow", Health: scanner.HealthSkip, Locked: true})
	if got := cs.Summary(); got != "1 ok, 1 denied" {
		t.Errorf("Summary = %q, want %q", got, "1 ok, 1 denied")
	}
}

func TestQuitKey(t *testing.T) {
	for _, k := range []tea.KeyPressMsg{press("q"), {Code: 'c', Mod: tea.ModCtrl}} {
		a := testApp(t)
		_, cmd := a.Update(k)
		if cmd == nil {
			t.Fatalf("key %q returned nil cmd, want quit", k.String())
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Errorf("key %q cmd did not produce QuitMsg", k.String())
		}
	}
}

func TestWindowSizeAndRelayout(t *testing.T) {
	a := testApp(t)
	if a.ready {
		t.Fatal("New() should not be ready before a WindowSizeMsg")
	}
	tests := []struct {
		w, h         int
		wantTooSmall bool
		wantBodyH    int
	}{
		{100, 40, false, 38},
		{80, 24, false, 22},
		{79, 24, true, 0},
		{80, 23, true, 0},
	}
	for _, tt := range tests {
		a.Update(tea.WindowSizeMsg{Width: tt.w, Height: tt.h})
		if !a.ready {
			t.Errorf("%dx%d: not ready", tt.w, tt.h)
		}
		if a.tooSmall != tt.wantTooSmall {
			t.Errorf("%dx%d: tooSmall=%v, want %v", tt.w, tt.h, a.tooSmall, tt.wantTooSmall)
		}
		if !tt.wantTooSmall && a.bodyH != tt.wantBodyH {
			t.Errorf("%dx%d: bodyH=%d, want %d", tt.w, tt.h, a.bodyH, tt.wantBodyH)
		}
	}
}

func TestDistribute(t *testing.T) {
	tests := []struct {
		total, n int
		want     []int
	}{
		{80, 3, []int{27, 27, 26}},
		{24, 2, []int{12, 12}},
		{7, 2, []int{4, 3}},
		{0, 3, []int{0, 0, 0}},
		{-5, 2, []int{0, 0}},
		{5, 0, nil},
	}
	for _, tt := range tests {
		got := distribute(tt.total, tt.n)
		if len(got) != len(tt.want) {
			t.Fatalf("distribute(%d,%d) len=%d, want %d", tt.total, tt.n, len(got), len(tt.want))
		}
		sum := 0
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("distribute(%d,%d)[%d]=%d, want %d", tt.total, tt.n, i, got[i], tt.want[i])
			}
			sum += got[i]
		}
		if tt.total > 0 && tt.n > 0 && sum != tt.total {
			t.Errorf("distribute(%d,%d) sums to %d, want %d", tt.total, tt.n, sum, tt.total)
		}
	}
}

func TestFmtUptime(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "?"},
		{-time.Hour, "?"},
		{30 * time.Minute, "30m"},
		{90 * time.Minute, "1h 30m"},
		{25 * time.Hour, "1d 1h"},
	}
	for _, c := range cases {
		if got := fmtUptime(c.d); got != c.want {
			t.Errorf("fmtUptime(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
