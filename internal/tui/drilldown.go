package tui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/medunes/misbar/internal/scanner"
)

// detailPreviewLines caps how much static content the drilldown previews; the
// full-screen view (Enter) shows all of it. tailPreviewLines caps live lines.
const (
	detailPreviewLines = 60
	tailPreviewLines   = 30
)

// drillFocus is which pane of the drilldown currently has focus.
type drillFocus uint8

const (
	focusList drillFocus = iota
	focusDetail
)

// drilldownModel is layer 2: a left artifact list and a right detail pane for
// one category. A plain renderer; App owns the state and injects it (including
// shared references to the live-line buffers and follow flags).
type drilldownModel struct {
	styles *Styles
	cat    *categoryState
	sel    int
	focus  drillFocus
	lines  map[scanner.ArtifactID][]lineEntry
	follow map[scanner.ArtifactID]bool
}

// clamp keeps the selection within the row range.
func (d *drilldownModel) clamp() {
	if d.cat == nil || len(d.cat.rows) == 0 {
		d.sel = 0
		return
	}
	d.sel = max(0, min(d.sel, len(d.cat.rows)-1))
}

// selected returns the currently selected row, or false when there is none.
func (d drilldownModel) selected() (artifactRow, bool) {
	if d.cat == nil || d.sel < 0 || d.sel >= len(d.cat.rows) {
		return artifactRow{}, false
	}
	return d.cat.rows[d.sel], true
}

// View renders the two panes side by side, filling exactly w×h.
func (d drilldownModel) View(w, h int) string {
	if d.cat == nil {
		return ""
	}
	listW := min(34, max(w/2, 1))
	detailW := max(w-listW, 1)
	left := d.renderList(listW, h)
	right := d.renderDetail(detailW, h)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (d drilldownModel) renderList(w, h int) string {
	var b strings.Builder
	b.WriteString(d.styles.PanelTitle.Render(fmt.Sprintf("%d  %s", d.cat.meta.ID, d.cat.meta.Label)))
	b.WriteString("\n\n")

	if len(d.cat.rows) == 0 {
		b.WriteString(d.styles.Dim.Render("(not yet implemented)"))
		return d.styles.panel(w, h, d.focus == focusList, b.String())
	}
	for i, row := range d.cat.rows {
		badge := "⚪"
		if r, ok := d.cat.result(row.id); ok {
			badge = r.Health.Badge()
			if r.Locked {
				badge = "🔒"
			}
		}
		if i == d.sel {
			b.WriteString(d.styles.Selected.Render("▸ "+badge+" "+row.label) + "\n")
		} else {
			b.WriteString("  " + badge + " " + row.label + "\n")
		}
	}
	return d.styles.panel(w, h, d.focus == focusList, b.String())
}

func (d drilldownModel) renderDetail(w, h int) string {
	row, ok := d.selected()
	if !ok {
		return d.styles.panel(w, h, d.focus == focusDetail, d.styles.Dim.Render("no artifact selected"))
	}

	var b strings.Builder
	b.WriteString(d.styles.PanelTitle.Render(row.label) + "\n")

	r, ok := d.cat.result(row.id)
	if !ok {
		b.WriteString("\n" + d.styles.Dim.Render("scanning…"))
		return d.styles.panel(w, h, d.focus == focusDetail, b.String())
	}

	b.WriteString(r.Health.Badge() + " " +
		d.styles.healthStyle(r.Health).Render(nonEmpty(r.Summary, r.Health.String())) + "\n")
	if r.Locked {
		b.WriteString(d.styles.HealthSkip.Render("Permission denied. Run with sudo for full access.") + "\n")
	}

	if len(r.Anomalies) > 0 {
		b.WriteString("\n" + d.styles.SectionTitle.Render("── Anomalies ──") + "\n")
		for _, a := range r.Anomalies {
			b.WriteString(d.styles.healthStyle(a.Severity).Render("⚠ "+a.Title) + "\n")
			if a.Detail != "" {
				b.WriteString(d.styles.Dim.Render("  "+a.Detail) + "\n")
			}
		}
	}

	// Prefer the live tail when lines have streamed; otherwise the static snapshot.
	if live := d.lines[row.id]; len(live) > 0 {
		b.WriteString("\n" + d.styles.SectionTitle.Render("── Live (tail) ──"))
		if d.follow[row.id] {
			b.WriteString("  " + d.styles.HealthOK.Render("● following"))
		}
		b.WriteByte('\n')
		for _, e := range live[max(0, len(live)-tailPreviewLines):] {
			b.WriteString(d.styles.severityStyle(e.sev).Render(e.text) + "\n")
		}
		b.WriteString(d.styles.Dim.Render("[Enter] full view"))
	} else if txt := strings.TrimRight(r.Content.Text, "\n"); txt != "" {
		b.WriteString("\n" + d.styles.SectionTitle.Render("── Content ──") + "\n")
		b.WriteString(previewText(txt, detailPreviewLines) + "\n")
		b.WriteString(d.styles.Dim.Render("[Enter] full view"))
	}
	return d.styles.panel(w, h, d.focus == focusDetail, b.String())
}

// nonEmpty returns s, or fallback when s is blank.
func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// previewText keeps at most maxLines lines, marking a cut with an ellipsis line.
func previewText(text string, maxLines int) string {
	lines := strings.Split(text, "\n")
	if len(lines) <= maxLines {
		return text
	}
	return strings.Join(lines[:maxLines], "\n") + "\n…"
}
