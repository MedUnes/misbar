// Package tui implements misbar's interactive terminal dashboard. The root App
// is the sole Bubble Tea model (Charm v2: only the root builds the tea.View);
// every sub-view is a plain renderer it composes.
package tui

import (
	"context"
	"fmt"
	"strconv"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/medunes/misbar/internal/scanner"
	"github.com/medunes/misbar/internal/tailer"
)

// Minimum usable terminal size. Below this the UI renders a notice instead of
// a cramped, overflow-prone layout.
const (
	minWidth  = 80
	minHeight = 24
)

// ringCap bounds the per-source live-line buffer so a firehose can't OOM.
const ringCap = 5000

// mode is the top-level navigation layer.
type mode uint8

const (
	modeOverview mode = iota
	modeDrilldown
	modeFullscreen
)

// overlayKind is a modal layer drawn over the current mode.
type overlayKind uint8

const (
	overlayNone overlayKind = iota
	overlayToolbox
	overlayHelp
)

// App is the sole tea.Model in the program. Sub-views are plain renderers it
// composes; App owns all state and the scan/tail lifecycle.
type App struct {
	styles *Styles
	keys   keyMap
	sys    sysInfo
	orch   *scanner.Orchestrator

	cats     []*categoryState                          // six fixed dashboard slots, grid order
	catIndex map[scanner.CategoryID]int                // CategoryID → slot index
	artCat   map[scanner.ArtifactID]scanner.CategoryID // ArtifactID → its category

	overview overviewModel
	drill    drilldownModel
	full     fullscreenModel
	tools    []toolStatus         // forensic-tool availability (toolbox footer)
	distro   scanner.DistroFamily // for install hints
	overlay  overlayKind          // modal layer over the current mode
	search   searchState          // in-content search (full-screen view)

	// Live tailing.
	lines       map[scanner.ArtifactID][]lineEntry // per-source ring buffers
	follow      map[scanner.ArtifactID]bool        // follow (auto-scroll) per source
	tailMgr     *tailer.Manager
	noLive      bool
	liveStarted bool // startLive has run once (kept idempotent across rescans)

	mode     mode
	focusCat int // 0..5

	scanCh    <-chan scanner.ScanResult
	scanning  bool
	parentCtx context.Context //nolint:containedctx // lifecycle ctx from main
	ctx       context.Context //nolint:containedctx // derived, cancelled on quit
	cancel    context.CancelFunc

	width, height, bodyW, bodyH int
	ready, tooSmall             bool
}

// New constructs the app over an orchestrator, with dark-default styles until
// the terminal answers RequestBackgroundColor.
func New(orch *scanner.Orchestrator) *App {
	st := NewStyles(true)
	a := &App{
		styles:    st,
		keys:      defaultKeyMap(),
		sys:       gatherSysInfo(),
		orch:      orch,
		mode:      modeOverview,
		catIndex:  make(map[scanner.CategoryID]int),
		artCat:    make(map[scanner.ArtifactID]scanner.CategoryID),
		lines:     make(map[scanner.ArtifactID][]lineEntry),
		follow:    make(map[scanner.ArtifactID]bool),
		parentCtx: context.Background(),
		ctx:       context.Background(), // non-nil until Init derives a cancelable one
		distro:    orch.Env().Distro,
	}
	a.buildCategories()
	a.overview = overviewModel{styles: st, cats: a.cats}
	return a
}

// buildCategories creates the six fixed dashboard slots and fills the artifact
// skeleton for whichever categories have a registered scanner.
func (a *App) buildCategories() {
	for i, meta := range scanner.AllCategoryMeta() {
		a.cats = append(a.cats, newCategoryState(meta))
		a.catIndex[meta.ID] = i
	}
	for _, art := range a.orch.Artifacts() {
		idx, ok := a.catIndex[art.Category]
		if !ok {
			continue
		}
		cs := a.cats[idx]
		cs.hasScanner = true
		cs.rows = append(cs.rows, artifactRow{id: art.ID, label: art.Label, needsRoot: art.NeedsRoot})
		a.artCat[art.ID] = art.Category
	}
}

// Init requests the background color and kicks off the async scan, returning the
// self-rescheduling waitForScan Cmd that drains results.
func (a *App) Init() tea.Cmd {
	a.ctx, a.cancel = context.WithCancel(a.parentCtx)
	a.scanCh = a.orch.Scan(a.ctx)
	a.scanning = true
	return tea.Batch(tea.RequestBackgroundColor, waitForScan(a.scanCh))
}

// Update routes by message type; keys are dispatched by mode.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.ready = true
		a.relayout()
		return a, nil

	case tea.BackgroundColorMsg:
		a.rebuildStyles(msg.IsDark())
		return a, nil

	case scanResultMsg:
		a.applyResult(msg.result)
		return a, waitForScan(a.scanCh) // re-arm to drain the next result

	case periodicResultMsg:
		a.applyResult(msg.result) // out-of-band: apply, do NOT re-arm the channel
		return a, nil

	case crossAnomaliesMsg:
		a.applyAggregates(msg.anomalies)
		return a, nil

	case scanDoneMsg:
		a.scanning = false
		// Compute cross-artifact anomalies once, and start live tailing once —
		// re-running startLive on every (re)scan would leak tailers and stack
		// duplicate refresh loops.
		cmds := []tea.Cmd{a.computeAggregates()}
		if !a.noLive && !a.liveStarted {
			a.liveStarted = true
			cmds = append(cmds, a.startLive())
		}
		return a, tea.Batch(cmds...)

	case lineMsg:
		a.appendLine(msg.line)
		if a.tailMgr == nil {
			return a, nil
		}
		return a, waitForLine(a.tailMgr.Lines())

	case liveDoneMsg:
		return a, nil // tailers shut down (ctx cancelled)

	case ssTickMsg:
		return a, tea.Batch(a.rescanSS(), tickSS())

	case tea.KeyPressMsg:
		return a.handleKey(msg)
	}
	return a, nil
}

// applyResult routes a scan result: the toolbox feeds the footer, everything
// else rolls into its category slot (results for unregistered categories are
// dropped).
func (a *App) applyResult(r scanner.ScanResult) {
	if r.Category == scanner.CatToolbox {
		a.tools = a.tools[:0]
		for _, f := range r.Findings {
			a.tools = append(a.tools, toolStatus{name: f.Message, ok: f.Severity == scanner.HealthOK})
		}
		return
	}
	if idx, ok := a.catIndex[r.Category]; ok {
		a.cats[idx].apply(r)
	}
}

// startLive begins tailing every file-based live source and starts the periodic
// ss refresh. Command-based live sources (ss) refresh via the tick, not a tail.
func (a *App) startLive() tea.Cmd {
	var srcs []tailer.Source
	for _, art := range a.orch.Artifacts() {
		if art.Mode == scanner.ModeLive && art.Live != nil && art.Live.Path != "" {
			srcs = append(srcs, tailer.Source{ID: tailer.SourceID(art.ID), Path: art.Live.Path})
			a.follow[art.ID] = true // follow by default
		}
	}
	if len(srcs) == 0 {
		return tickSS()
	}
	a.tailMgr = tailer.NewManager()
	a.tailMgr.Start(a.ctx, srcs)
	return tea.Batch(waitForLine(a.tailMgr.Lines()), tickSS())
}

// appendLine buffers a tailed line into its source ring and, when that source is
// on screen in full-screen mode, refreshes the viewport (auto-scrolling if
// following).
func (a *App) appendLine(l tailer.LineMsg) {
	id := scanner.ArtifactID(l.Src)
	buf := append(a.lines[id], lineEntry{text: l.Line, sev: l.Sev})
	if len(buf) > ringCap {
		buf = buf[len(buf)-ringCap:]
	}
	a.lines[id] = buf

	// Refresh the full-screen view in place — but not while a search is active,
	// or the rewrite would wipe the match highlighting and desync match indices.
	if a.mode == modeFullscreen && a.full.sourceID == id && !a.search.active() {
		a.full.setLines(a.styles, a.lines[id])
		if a.follow[id] {
			a.full.vp.GotoBottom()
		}
	}
}

// rescanSS re-runs the listening-ports artifact through the orchestrator's
// timeout+recover wrapper and feeds it back as an out-of-band periodicResultMsg
// (which does not re-arm the closed scan channel).
func (a *App) rescanSS() tea.Cmd {
	return func() tea.Msg {
		res, ok := a.orch.RunArtifact(a.ctx, "listening-ports")
		if !ok {
			return nil
		}
		return periodicResultMsg{res}
	}
}

// computeAggregates runs the cross-artifact detectors off the UI thread.
func (a *App) computeAggregates() tea.Cmd {
	env := a.orch.Env()
	return func() tea.Msg { return crossAnomaliesMsg{scanner.AggregateAnomalies(env)} }
}

// applyAggregates attaches each aggregate anomaly to its artifact's category so
// the overview badge and summary reflect brute-force / rate-spike detections.
func (a *App) applyAggregates(anoms []scanner.Anomaly) {
	for _, cs := range a.cats {
		cs.aggregate = nil // recomputable: replace, don't accumulate across rescans
	}
	for _, an := range anoms {
		if catID, ok := a.artCat[an.Artifact]; ok {
			if idx, ok := a.catIndex[catID]; ok {
				a.cats[idx].aggregate = append(a.cats[idx].aggregate, an)
			}
		}
	}
}

// rebuildStyles rebuilds the style set and propagates it to every sub-view.
func (a *App) rebuildStyles(isDark bool) {
	a.styles = NewStyles(isDark)
	a.overview.styles = a.styles
	a.drill.styles = a.styles
	a.full.styles = a.styles
}

// quit cancels the scan/tail context and tells the program to exit.
func (a *App) quit() (tea.Model, tea.Cmd) {
	if a.cancel != nil {
		a.cancel() // stop scan + tail goroutines before we exit
	}
	return a, tea.Quit
}

// handleKey applies the global quit key, then delegates to the active mode.
func (a *App) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	// While a search query is being typed, keys build it — so a literal `q`
	// isn't a quit. Only ctrl+c force-quits from the search prompt.
	if a.search.inputting {
		if msg.String() == "ctrl+c" {
			return a.quit()
		}
		a.handleSearchInput(msg)
		return a, nil
	}
	if key.Matches(msg, a.keys.Quit) {
		return a.quit()
	}
	// A modal overlay captures keys: esc, or the toggling key, closes it.
	if a.overlay != overlayNone {
		if key.Matches(msg, a.keys.Back) || key.Matches(msg, a.keys.Toolbox) || key.Matches(msg, a.keys.Help) {
			a.overlay = overlayNone
		}
		return a, nil
	}
	// Help is available from any mode.
	if key.Matches(msg, a.keys.Help) {
		a.overlay = overlayHelp
		return a, nil
	}
	// Manual rescan from the overview or a drilldown.
	if key.Matches(msg, a.keys.Rescan) && (a.mode == modeOverview || a.mode == modeDrilldown) {
		return a, a.rescan()
	}
	switch a.mode {
	case modeDrilldown:
		return a.handleDrilldownKey(msg)
	case modeFullscreen:
		return a.handleFullscreenKey(msg)
	default:
		return a.handleOverviewKey(msg)
	}
}

func (a *App) handleOverviewKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, a.keys.Cat):
		if n, err := strconv.Atoi(msg.String()); err == nil && n >= 1 && n <= len(a.cats) {
			a.focusCat = n - 1
			a.enterDrilldown()
		}
	case key.Matches(msg, a.keys.Enter):
		a.enterDrilldown()
	case key.Matches(msg, a.keys.Toolbox):
		a.overlay = overlayToolbox
	case key.Matches(msg, a.keys.Next):
		a.focusCat = (a.focusCat + 1) % len(a.cats)
	case key.Matches(msg, a.keys.Prev):
		a.focusCat = (a.focusCat + len(a.cats) - 1) % len(a.cats)
	case key.Matches(msg, a.keys.Right):
		a.moveFocus(0, 1)
	case key.Matches(msg, a.keys.Left):
		a.moveFocus(0, -1)
	case key.Matches(msg, a.keys.Down):
		a.moveFocus(1, 0)
	case key.Matches(msg, a.keys.Up):
		a.moveFocus(-1, 0)
	}
	return a, nil
}

func (a *App) handleDrilldownKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, a.keys.Back):
		a.mode = modeOverview
	case key.Matches(msg, a.keys.Cat):
		if n, err := strconv.Atoi(msg.String()); err == nil && n >= 1 && n <= len(a.cats) {
			a.focusCat = n - 1
			a.enterDrilldown()
		}
	case key.Matches(msg, a.keys.Down):
		a.drill.sel++
		a.drill.clamp()
	case key.Matches(msg, a.keys.Up):
		a.drill.sel--
		a.drill.clamp()
	case key.Matches(msg, a.keys.Next):
		a.drill.focus = focusDetail - a.drill.focus // toggle list ↔ detail
	case key.Matches(msg, a.keys.Follow):
		if row, ok := a.drill.selected(); ok {
			a.follow[row.id] = !a.follow[row.id]
		}
	case key.Matches(msg, a.keys.Enter):
		a.enterFullscreen()
	}
	return a, nil
}

func (a *App) handleFullscreenKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, a.keys.Back):
		a.clearSearch()
		a.mode = modeDrilldown
		return a, nil
	case key.Matches(msg, a.keys.Search):
		a.search = searchState{inputting: true}
		return a, nil
	case key.Matches(msg, a.keys.SearchNext):
		a.cycleMatch(1)
		return a, nil
	case key.Matches(msg, a.keys.SearchPrev):
		a.cycleMatch(-1)
		return a, nil
	case key.Matches(msg, a.keys.Yank):
		return a, tea.SetClipboard(a.full.currentLine())
	case key.Matches(msg, a.keys.Follow):
		id := a.full.sourceID
		a.follow[id] = !a.follow[id]
		if a.follow[id] {
			a.full.vp.GotoBottom()
		}
		return a, nil
	}
	switch msg.String() {
	case "g":
		a.full.vp.GotoTop()
		return a, nil
	case "G":
		a.full.vp.GotoBottom()
		return a, nil
	}
	return a, a.full.update(msg)
}

// rescan clears results and re-runs the static scan. It is a no-op while a scan
// is already in flight, which keeps the channel/Cmd bookkeeping race-free.
func (a *App) rescan() tea.Cmd {
	if a.scanning {
		return nil
	}
	for _, c := range a.cats {
		c.byArt = make(map[scanner.ArtifactID]scanner.ScanResult)
	}
	a.tools = a.tools[:0]
	a.scanCh = a.orch.Scan(a.ctx)
	a.scanning = true
	return waitForScan(a.scanCh)
}

// enterDrilldown opens layer 2 for the focused category.
func (a *App) enterDrilldown() {
	a.mode = modeDrilldown
	a.drill = drilldownModel{styles: a.styles, cat: a.cats[a.focusCat], lines: a.lines, follow: a.follow}
}

// openCategory deep-links straight into a category's drilldown (from --category).
// n is 1-based; out-of-range values are ignored and the overview is shown.
func (a *App) openCategory(n int) {
	if n >= 1 && n <= len(a.cats) {
		a.focusCat = n - 1
		a.enterDrilldown()
	}
}

// enterFullscreen opens layer 3 for the selected artifact: its live tail if any
// lines have streamed, otherwise its static result.
func (a *App) enterFullscreen() {
	row, ok := a.drill.selected()
	if !ok {
		return
	}
	if lines := a.lines[row.id]; len(lines) > 0 {
		a.full = newFullscreenLines(a.styles, row.label, row.id, lines)
	} else {
		r, ok := a.drill.cat.result(row.id)
		if !ok {
			return // nothing scanned yet
		}
		a.full = newFullscreen(a.styles, row.label, r)
		// Set the source ID even from the static snapshot so a live artifact that
		// hasn't streamed a line yet still refreshes once lines arrive.
		a.full.sourceID = row.id
	}
	a.full.resize(a.bodyW, a.bodyH)
	if a.follow[row.id] {
		a.full.vp.GotoBottom()
	}
	a.mode = modeFullscreen
}

// moveFocus shifts the highlighted panel within the 3×2 grid, wrapping edges.
func (a *App) moveFocus(dRow, dCol int) {
	row, col := a.focusCat/gridCols, a.focusCat%gridCols
	row = (row + dRow + gridRows) % gridRows
	col = (col + dCol + gridCols) % gridCols
	a.focusCat = row*gridCols + col
}

// relayout is the single owner of geometry: sets the too-small flag, computes
// the body rect, and resizes the full-screen viewport when active.
func (a *App) relayout() {
	a.tooSmall = a.width < minWidth || a.height < minHeight
	if a.tooSmall {
		return
	}
	a.bodyW = a.width
	a.bodyH = max(a.height-2, 0) // minus top bar + bottom bar
	if a.full.ready {
		a.full.resize(a.bodyW, a.bodyH)
	}
}

// View builds the single tea.View for the frame. AltScreen is set every frame
// (Charm v2 requirement) or the program drops out of the alternate buffer.
func (a *App) View() tea.View {
	v := tea.View{AltScreen: true}
	if !a.ready {
		return v
	}
	if a.tooSmall {
		v.Content = a.renderTooSmall()
		return v
	}
	switch a.overlay {
	case overlayToolbox:
		v.Content = a.styles.toolboxOverlay(a.width, a.height, a.tools, a.distro)
		return v
	case overlayHelp:
		v.Content = a.styles.helpOverlay(a.width, a.height, a.keys)
		return v
	}

	top := a.styles.topBar(a.width, a.sys)
	bottomText := a.hint()
	if a.mode == modeFullscreen && a.search.active() {
		bottomText = a.searchStatus()
	}
	bottom := a.styles.bottomBar(a.width, bottomText)

	var body string
	switch a.mode {
	case modeDrilldown:
		body = a.drill.View(a.bodyW, a.bodyH)
	case modeFullscreen:
		body = a.full.View(a.bodyW, a.bodyH)
	default:
		// Overview reserves one row above the bottom bar for the toolbox footer.
		a.overview.focus = a.focusCat
		grid := a.overview.View(a.bodyW, max(a.bodyH-1, 0))
		body = lipgloss.JoinVertical(lipgloss.Left, grid, a.styles.toolboxBar(a.width, a.tools))
	}
	v.Content = lipgloss.JoinVertical(lipgloss.Left, top, body, bottom)
	return v
}

// hint returns the mode-appropriate bottom-bar keybind line.
func (a *App) hint() string {
	switch a.mode {
	case modeDrilldown:
		return "j/k select · tab pane · enter open · f follow · 1–6 category · esc back · q quit"
	case modeFullscreen:
		return "j/k scroll · g/G top/bottom · f follow · esc back · q quit"
	default:
		return "1–6 open · tab cycle · enter drill in · t toolbox · q quit"
	}
}

// renderTooSmall centers a notice explaining the minimum terminal size.
func (a *App) renderTooSmall() string {
	msg := fmt.Sprintf("Terminal too small\nneed at least %d×%d — have %d×%d",
		minWidth, minHeight, a.width, a.height)
	return lipgloss.Place(max(a.width, 1), max(a.height, 1),
		lipgloss.Center, lipgloss.Center, a.styles.Notice.Render(msg))
}
