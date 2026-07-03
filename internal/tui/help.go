package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/lipgloss/v2"
)

// helpOverlay renders a centered panel listing every keybinding, grouped.
func (s *Styles) helpOverlay(w, h int, km keyMap) string {
	row := func(b key.Binding) string {
		hb := b.Help()
		return "  " + s.Selected.Render(fmt.Sprintf("%-11s", hb.Key)) + s.Dim.Render(hb.Desc)
	}
	group := func(title string, binds ...key.Binding) string {
		var b strings.Builder
		b.WriteString(s.SectionTitle.Render(title))
		b.WriteByte('\n')
		for _, bind := range binds {
			b.WriteString(row(bind))
			b.WriteByte('\n')
		}
		return b.String()
	}

	var b strings.Builder
	b.WriteString(s.PanelTitle.Render("misbar — keybindings"))
	b.WriteString("\n\n")
	b.WriteString(group("Navigate", km.Cat, km.Next, km.Prev, km.Up, km.Down, km.Left, km.Right, km.Enter, km.Back))
	b.WriteByte('\n')
	b.WriteString(group("Content", km.Search, km.SearchNext, km.SearchPrev, km.Yank, km.Follow))
	b.WriteByte('\n')
	b.WriteString(group("Global", km.Rescan, km.Toolbox, km.Help, km.Quit))
	b.WriteString("\n")
	b.WriteString(s.Dim.Render("[?/esc] close"))

	return lipgloss.Place(max(w, 1), max(h, 1), lipgloss.Center, lipgloss.Center, s.Overlay.Render(b.String()))
}
