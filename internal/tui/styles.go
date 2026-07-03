package tui

import (
	"charm.land/lipgloss/v2"

	"github.com/medunes/misbar/internal/parser"
	"github.com/medunes/misbar/internal/scanner"
)

// Health badge colors from misbar-spec.md (fixed hex, legible on light and dark).
var (
	colorOK   = lipgloss.Color("#22c55e") // green-500  — no anomalies
	colorWarn = lipgloss.Color("#eab308") // yellow-500 — warnings present
	colorCrit = lipgloss.Color("#ef4444") // red-500    — anomalies, act now
	colorSkip = lipgloss.Color("#6b7280") // gray-500   — not found / denied
)

// Styles holds every lipgloss.Style the TUI renders with. It is rebuilt once per
// background-color change (light vs dark) in App.Update's BackgroundColorMsg
// handler, so styling never relies on a global renderer (removed in lipgloss v2).
type Styles struct {
	isDark bool

	Notice  lipgloss.Style // centered "terminal too small" notice
	Overlay lipgloss.Style // bordered box for centered overlays

	Panel             lipgloss.Style // inactive panel frame
	PanelFocused      lipgloss.Style // active panel frame
	PanelTitle        lipgloss.Style // panel header, inactive
	PanelTitleFocused lipgloss.Style // panel header, active
	Dim               lipgloss.Style // muted body text ("Scanning…")
	Selected          lipgloss.Style // highlighted list row
	SectionTitle      lipgloss.Style // "── Anomalies ──" separators
	SearchMatch       lipgloss.Style // a line matching the search query
	SearchCurrent     lipgloss.Style // the current search match

	TopBar    lipgloss.Style // hostname/title segment
	TopBarKey lipgloss.Style // access/uptime segment
	BottomBar lipgloss.Style // keybind hint line

	// Health foregrounds keyed by severity, used for badges and summaries.
	HealthOK   lipgloss.Style
	HealthWarn lipgloss.Style
	HealthCrit lipgloss.Style
	HealthSkip lipgloss.Style

	// Log-line severity highlighting for live tails (spec color table).
	SevEmerg  lipgloss.Style
	SevCrit   lipgloss.Style
	SevErr    lipgloss.Style
	SevWarn   lipgloss.Style
	SevNotice lipgloss.Style
	SevInfo   lipgloss.Style
	SevDebug  lipgloss.Style
}

// pick returns the dark or light variant of a hex color for the given mode.
func pick(isDark bool, dark, light string) string {
	if isDark {
		return dark
	}
	return light
}

// NewStyles builds the full style set for a light or dark terminal background.
func NewStyles(isDark bool) *Styles {
	border := lipgloss.Color(pick(isDark, "#3f3f46", "#d4d4d8")) // dim frame
	focus := lipgloss.Color("#22d3ee")                           // cyan accent
	dim := lipgloss.Color(pick(isDark, "#9ca3af", "#6b7280"))    // muted text
	title := lipgloss.Color(pick(isDark, "#f4f4f5", "#18181b"))  // headings

	s := &Styles{isDark: isDark}

	s.Notice = lipgloss.NewStyle().Foreground(colorWarn).Bold(true).Align(lipgloss.Center)
	s.Overlay = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(focus).Padding(1, 2)

	s.Panel = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1)
	s.PanelFocused = s.Panel.BorderForeground(focus)
	s.PanelTitle = lipgloss.NewStyle().Foreground(title).Bold(true)
	s.PanelTitleFocused = lipgloss.NewStyle().Foreground(focus).Bold(true)
	s.Dim = lipgloss.NewStyle().Foreground(dim)
	s.Selected = lipgloss.NewStyle().Foreground(focus).Bold(true)
	s.SectionTitle = lipgloss.NewStyle().Foreground(dim).Bold(true)
	s.SearchMatch = lipgloss.NewStyle().Foreground(colorWarn).Bold(true)
	s.SearchCurrent = lipgloss.NewStyle().Foreground(lipgloss.Color("#000000")).Background(colorWarn).Bold(true)

	s.TopBar = lipgloss.NewStyle().Foreground(title).Bold(true)
	s.TopBarKey = lipgloss.NewStyle().Foreground(dim)
	s.BottomBar = lipgloss.NewStyle().Foreground(dim)

	s.HealthOK = lipgloss.NewStyle().Foreground(colorOK)
	s.HealthWarn = lipgloss.NewStyle().Foreground(colorWarn)
	s.HealthCrit = lipgloss.NewStyle().Foreground(colorCrit).Bold(true)
	s.HealthSkip = lipgloss.NewStyle().Foreground(colorSkip)

	cyan := lipgloss.Color("#22d3ee")
	s.SevEmerg = lipgloss.NewStyle().Foreground(colorCrit).Bold(true).Reverse(true)
	s.SevCrit = lipgloss.NewStyle().Foreground(colorCrit).Bold(true)
	s.SevErr = lipgloss.NewStyle().Foreground(colorCrit)
	s.SevWarn = lipgloss.NewStyle().Foreground(colorWarn)
	s.SevNotice = lipgloss.NewStyle().Foreground(cyan)
	s.SevInfo = s.Dim
	s.SevDebug = lipgloss.NewStyle().Foreground(colorSkip)

	return s
}

// severityStyle maps a parsed log severity to its highlight style.
func (s *Styles) severityStyle(sev parser.Severity) lipgloss.Style {
	switch sev {
	case parser.SevEmerg, parser.SevAlert:
		return s.SevEmerg
	case parser.SevCrit:
		return s.SevCrit
	case parser.SevErr:
		return s.SevErr
	case parser.SevWarning:
		return s.SevWarn
	case parser.SevNotice:
		return s.SevNotice
	case parser.SevDebug:
		return s.SevDebug
	default:
		return s.SevInfo
	}
}

// panel frames body inside a bordered box of exactly w×h. body is pre-sized to
// the inner content region and clipped so it can never overflow the box (which
// would break the surrounding layout).
func (s *Styles) panel(w, h int, focused bool, body string) string {
	frame := s.Panel
	if focused {
		frame = s.PanelFocused
	}
	// Panel = border(2) + horizontal padding(2); inner region is w-4 × h-2.
	inner := lipgloss.NewStyle().
		Width(max(w-4, 1)).
		MaxHeight(max(h-2, 1)).
		Render(body)
	return frame.Width(w).Height(h).Render(inner)
}

// healthStyle returns the foreground style for a Health severity.
func (s *Styles) healthStyle(h scanner.Health) lipgloss.Style {
	switch h {
	case scanner.HealthOK:
		return s.HealthOK
	case scanner.HealthWarn:
		return s.HealthWarn
	case scanner.HealthCrit:
		return s.HealthCrit
	default:
		return s.HealthSkip
	}
}
