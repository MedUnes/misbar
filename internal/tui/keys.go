package tui

import "charm.land/bubbles/v2/key"

// keyMap holds every key binding. Bindings carry help text so a help overlay
// (M5) and the bottom bar can render from a single source of truth.
type keyMap struct {
	Cat        key.Binding // 1..6 — jump to a category drilldown
	Next       key.Binding // tab
	Prev       key.Binding // shift+tab
	Up         key.Binding
	Down       key.Binding
	Left       key.Binding
	Right      key.Binding
	Enter      key.Binding // drill in / open full view
	Back       key.Binding // esc
	Follow     key.Binding // f — toggle live-tail follow
	Toolbox    key.Binding // t — toolbox install hints
	Help       key.Binding // ? — help overlay
	Rescan     key.Binding // r — rescan static artifacts
	Yank       key.Binding // y — copy current line
	Search     key.Binding // / — search within content
	SearchNext key.Binding // n
	SearchPrev key.Binding // N
	Quit       key.Binding
}

func defaultKeyMap() keyMap {
	return keyMap{
		Cat:        key.NewBinding(key.WithKeys("1", "2", "3", "4", "5", "6"), key.WithHelp("1–6", "category")),
		Next:       key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "cycle")),
		Prev:       key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "cycle back")),
		Up:         key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:       key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Left:       key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("←/h", "left")),
		Right:      key.NewBinding(key.WithKeys("right", "l"), key.WithHelp("→/l", "right")),
		Enter:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open")),
		Back:       key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		Follow:     key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "follow")),
		Toolbox:    key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "toolbox")),
		Help:       key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Rescan:     key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "rescan")),
		Yank:       key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "yank line")),
		Search:     key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
		SearchNext: key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "next match")),
		SearchPrev: key.NewBinding(key.WithKeys("N"), key.WithHelp("N", "prev match")),
		Quit:       key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}
