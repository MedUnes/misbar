package tui

import (
	"strings"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/medunes/misbar/internal/scanner"
)

// fullscreenModel is layer 3: one artifact's complete content in a scrollable
// viewport (bubbles v2). App drives resize and key routing. sourceID is set for
// live artifacts so streamed lines can refresh the viewport in place. It keeps
// both the styled content and its plain lines (for search and yank).
type fullscreenModel struct {
	styles   *Styles
	label    string
	sourceID scanner.ArtifactID
	vp       viewport.Model
	ready    bool

	styled   string   // original colored content
	rawLines []string // plain lines, aligned with styled, for search/yank
}

// newFullscreen builds the full-screen view for one artifact's static result.
func newFullscreen(styles *Styles, label string, r scanner.ScanResult) fullscreenModel {
	f := fullscreenModel{styles: styles, label: label, ready: true}
	f.vp = viewport.New()
	f.setStyled(f.body(r))
	return f
}

// newFullscreenLines builds the full-screen view for a live source's tailed
// lines, colored by severity.
func newFullscreenLines(styles *Styles, label string, id scanner.ArtifactID, lines []lineEntry) fullscreenModel {
	f := fullscreenModel{styles: styles, label: label, sourceID: id, ready: true}
	f.vp = viewport.New()
	f.setStyled(renderLines(styles, lines))
	return f
}

// setLines replaces the viewport content with the current tailed lines.
func (f *fullscreenModel) setLines(styles *Styles, lines []lineEntry) {
	f.setStyled(renderLines(styles, lines))
}

// setStyled stores styled content, derives its plain lines, and shows it.
func (f *fullscreenModel) setStyled(content string) {
	f.styled = content
	f.rawLines = strings.Split(ansi.Strip(content), "\n")
	f.vp.SetContent(content)
}

// restore re-displays the original styled content (after clearing a search).
func (f *fullscreenModel) restore() { f.vp.SetContent(f.styled) }

// currentLine returns the plain text of the line at the top of the viewport —
// the target of the yank command.
func (f fullscreenModel) currentLine() string {
	i := f.vp.YOffset()
	if i < 0 || i >= len(f.rawLines) {
		return ""
	}
	return f.rawLines[i]
}

// find returns the indices of plain lines containing query (case-insensitive).
func (f fullscreenModel) find(query string) []int {
	if query == "" {
		return nil
	}
	q := strings.ToLower(query)
	var out []int
	for i, line := range f.rawLines {
		if strings.Contains(strings.ToLower(line), q) {
			out = append(out, i)
		}
	}
	return out
}

// highlight re-renders the plain content with matching lines styled (the current
// match emphasized) and scrolls the current match into view.
func (f *fullscreenModel) highlight(matches []int, current int) {
	isMatch := make(map[int]bool, len(matches))
	for _, m := range matches {
		isMatch[m] = true
	}
	cur := -1
	if current >= 0 && current < len(matches) {
		cur = matches[current]
	}

	var b strings.Builder
	for i, line := range f.rawLines {
		switch {
		case i == cur:
			b.WriteString(f.styles.SearchCurrent.Render(line))
		case isMatch[i]:
			b.WriteString(f.styles.SearchMatch.Render(line))
		default:
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}
	f.vp.SetContent(b.String())
	if cur >= 0 {
		f.vp.SetYOffset(cur)
	}
}

// renderLines joins tailed lines, each highlighted by its severity.
func renderLines(styles *Styles, lines []lineEntry) string {
	var b strings.Builder
	for _, e := range lines {
		b.WriteString(styles.severityStyle(e.sev).Render(e.text))
		b.WriteByte('\n')
	}
	return b.String()
}

// resize fits the viewport below the header line.
func (f *fullscreenModel) resize(w, h int) {
	f.vp.SetWidth(max(w, 1))
	f.vp.SetHeight(max(h-1, 1)) // header
}

// update forwards a message to the viewport (scrolling).
func (f *fullscreenModel) update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.vp, cmd = f.vp.Update(msg)
	return cmd
}

// View stacks a header and the scrolling body. The keybind/search line lives in
// the app's bottom bar.
func (f fullscreenModel) View(_, _ int) string {
	header := f.styles.PanelTitle.Render(f.label)
	return lipgloss.JoinVertical(lipgloss.Left, header, f.vp.View())
}

// body renders the full detail: summary, anomalies, findings, and raw content.
func (f fullscreenModel) body(r scanner.ScanResult) string {
	var b strings.Builder
	b.WriteString(r.Health.Badge() + " " +
		f.styles.healthStyle(r.Health).Render(nonEmpty(r.Summary, r.Health.String())) + "\n")
	if r.Locked {
		b.WriteString(f.styles.HealthSkip.Render("Permission denied. Run with sudo for full access.") + "\n")
	}

	if len(r.Anomalies) > 0 {
		b.WriteString("\n" + f.styles.SectionTitle.Render("── Anomalies ──") + "\n")
		for _, a := range r.Anomalies {
			b.WriteString(f.styles.healthStyle(a.Severity).Render("⚠ "+a.Title) + "\n")
			if a.Detail != "" {
				b.WriteString(f.styles.Dim.Render("  "+a.Detail) + "\n")
			}
			for _, e := range a.Evidence {
				b.WriteString(f.styles.Dim.Render("    "+e) + "\n")
			}
		}
	}

	if len(r.Findings) > 0 {
		b.WriteString("\n" + f.styles.SectionTitle.Render("── Findings ──") + "\n")
		for _, fd := range r.Findings {
			b.WriteString(f.styles.healthStyle(fd.Severity).Render("• "+fd.Message) + "\n")
		}
	}

	if txt := strings.TrimRight(r.Content.Text, "\n"); txt != "" {
		title := "── Content ──"
		if r.Content.Truncated {
			title += " (truncated)"
		}
		b.WriteString("\n" + f.styles.SectionTitle.Render(title) + "\n" + txt + "\n")
	}
	return b.String()
}
