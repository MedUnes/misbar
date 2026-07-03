package tui

import (
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/medunes/misbar/internal/scanner"
)

// toolStatus is one forensic tool's availability, shown in the footer.
type toolStatus struct {
	name string
	ok   bool
}

// toolboxBar renders the forensic-tool availability footer:
// "Toolbox: dd ✓  md5sum ✓  sleuthkit ✗ …", clipped to width.
func (s *Styles) toolboxBar(width int, tools []toolStatus) string {
	if len(tools) == 0 {
		return s.Dim.Width(width).MaxHeight(1).Render("Toolbox: scanning…")
	}
	parts := make([]string, 0, len(tools))
	for _, t := range tools {
		mark := s.HealthCrit.Render("✗")
		if t.ok {
			mark = s.HealthOK.Render("✓")
		}
		parts = append(parts, t.name+" "+mark)
	}
	line := s.SectionTitle.Render("Toolbox:") + " " + strings.Join(parts, "  ")
	return lipgloss.NewStyle().MaxWidth(width).Inline(true).Render(line)
}

// forensic-tool install hints. Some tools ship via the package manager; others
// (plaso, volatility, rekall) are typically installed via pip.
var (
	toolPkg = map[string]string{
		"dd": "coreutils", "md5sum": "coreutils", "sha256sum": "coreutils",
		"sleuthkit": "sleuthkit", "foremost": "foremost", "autopsy": "autopsy",
	}
	toolPip = map[string]string{
		"log2timeline": "plaso", "plaso": "plaso",
		"rekall": "rekall", "volatility": "volatility3",
	}
)

func installHint(tool, mgr string) string {
	if pkg, ok := toolPip[tool]; ok {
		return "pip install " + pkg
	}
	if pkg, ok := toolPkg[tool]; ok {
		return mgr + " " + pkg
	}
	return mgr + " " + tool
}

// toolboxOverlay renders the centered install-hint panel: each tool with its
// availability and, when missing, a distro-appropriate install command. misbar
// never installs anything — these are copy-paste suggestions only.
func (s *Styles) toolboxOverlay(w, h int, tools []toolStatus, distro scanner.DistroFamily) string {
	mgr := "apt install"
	if distro == scanner.FamilyRHEL {
		mgr = "dnf install"
	}

	var b strings.Builder
	b.WriteString(s.PanelTitle.Render("Toolbox — forensic tools"))
	b.WriteString("\n\n")
	missing := 0
	for _, t := range tools {
		if t.ok {
			b.WriteString(s.HealthOK.Render("  ✓ "+t.name) + "\n")
			continue
		}
		missing++
		b.WriteString(s.HealthCrit.Render("  ✗ "+t.name) + s.Dim.Render("   →  "+installHint(t.name, mgr)) + "\n")
	}
	b.WriteByte('\n')
	if missing == 0 {
		b.WriteString(s.HealthOK.Render("All forensic tools are available.") + "\n")
	}
	b.WriteString(s.Dim.Render("misbar never installs anything — run a command yourself.") + "\n")
	b.WriteString(s.Dim.Render("[t/esc] close"))

	return lipgloss.Place(max(w, 1), max(h, 1), lipgloss.Center, lipgloss.Center, s.Overlay.Render(b.String()))
}
