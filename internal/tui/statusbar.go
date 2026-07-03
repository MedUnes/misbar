package tui

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

// sysInfo is the chrome shown in the top bar. It is host metadata, not a
// forensic artifact — gathered once at startup, never rescanned.
type sysInfo struct {
	hostname string
	user     string
	isRoot   bool
	uptime   time.Duration
}

// gatherSysInfo reads hostname, current user, euid, and uptime. Every field
// degrades to a sensible placeholder rather than failing.
func gatherSysInfo() sysInfo {
	info := sysInfo{hostname: "unknown", user: "unknown"}

	if h, err := os.Hostname(); err == nil && h != "" {
		info.hostname = h
	}
	info.isRoot = os.Geteuid() == 0
	if u, err := user.Current(); err == nil && u.Username != "" {
		info.user = u.Username
	} else if n := os.Getenv("USER"); n != "" {
		info.user = n
	}
	info.uptime = readUptime()
	return info
}

// readUptime parses the first field of /proc/uptime (seconds since boot).
func readUptime() time.Duration {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// fmtUptime renders a duration as a compact "3d 4h" / "5h 12m" / "8m" string.
func fmtUptime(d time.Duration) string {
	if d <= 0 {
		return "?"
	}
	totalHours := int(d.Hours())
	days, hours := totalHours/24, totalHours%24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

// access renders the privilege level shown in the top bar.
func (info sysInfo) access() string {
	if info.isRoot {
		return "[root] full access"
	}
	return fmt.Sprintf("[user: %s] partial access", info.user)
}

// topBar renders the hostname/title on the left and access/uptime on the right,
// justified to fill width. It never exceeds width (ANSI-aware truncation).
func (s *Styles) topBar(width int, info sysInfo) string {
	left := s.TopBar.Render("misbar") + s.Dim.Render("  "+info.hostname)
	right := s.TopBarKey.Render(info.access() + "  up " + fmtUptime(info.uptime))

	gap := max(width-lipgloss.Width(left)-lipgloss.Width(right), 1)
	line := left + strings.Repeat(" ", gap) + right
	return lipgloss.NewStyle().MaxWidth(width).Render(line)
}

// bottomBar renders the given keybind hint line, padded to the full width.
func (s *Styles) bottomBar(width int, hint string) string {
	return s.BottomBar.Width(width).MaxHeight(1).Render(hint)
}
