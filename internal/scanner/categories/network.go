package categories

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/medunes/misbar/internal/scanner"
)

// network implements the category-2 scanner: hosts/DNS config and listening
// ports.
type network struct{}

// Network returns the category-2 scanner.
func Network() scanner.Scanner { return network{} }

func (network) Meta() scanner.CategoryMeta {
	return scanner.CategoryMeta{ID: scanner.CatNetwork, Label: "Network"}
}

func (network) Artifacts(env *scanner.Env) []scanner.Artifact {
	cat := scanner.CatNetwork
	ufw := env.Path("/var/log/ufw.log")
	iptables := env.Path("/var/log/iptables.log")
	return []scanner.Artifact{
		{ID: "listening-ports", Category: cat, Label: "ss -tulnp", Mode: scanner.ModeLive,
			Live: &scanner.LiveSource{Cmd: []string{"ss", "-tulnp"}, Interval: 10}, Scan: scanListeningPorts},
		{ID: "hosts", Category: cat, Label: "/etc/hosts", Scan: scanHosts},
		{ID: "resolv.conf", Category: cat, Label: "/etc/resolv.conf", Scan: scanResolv},
		{ID: "interfaces", Category: cat, Label: "/etc/network/interfaces", Distros: scanner.DistroSet(scanner.FamilyDebian), Scan: simpleFile("interfaces", cat, "/etc/network/interfaces")},
		{ID: "network-scripts", Category: cat, Label: "/etc/sysconfig/network-scripts/", Distros: scanner.DistroSet(scanner.FamilyRHEL), Scan: scanDirRecent("network-scripts", cat, "/etc/sysconfig/network-scripts", scanner.RecentWindow7d, "network script")},
		{ID: "ufw.log", Category: cat, Label: ufw, Mode: scanner.ModeLive, Distros: scanner.DistroSet(scanner.FamilyDebian),
			Live: &scanner.LiveSource{Path: ufw}, Scan: logArtifact("ufw.log", cat, ufw)},
		{ID: "iptables.log", Category: cat, Label: iptables, Mode: scanner.ModeLive,
			Live: &scanner.LiveSource{Path: iptables}, Scan: logArtifact("iptables.log", cat, iptables)},
	}
}

// commonDomains are well-known hosts that should never resolve to a non-local IP
// via /etc/hosts — a classic hijack.
var commonDomains = []string{
	"google.com", "github.com", "facebook.com", "cloudflare.com",
	"amazonaws.com", "microsoft.com", "apple.com", "windowsupdate.com",
}

// scanHosts flags /etc/hosts entries mapping a well-known domain to a
// non-localhost address.
func scanHosts(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := fileResult("hosts", scanner.CatNetwork, env.Path("/etc/hosts"))
	if res.Err != nil {
		setAbsent(&res)
		return res
	}

	var rogue []string
	for _, line := range scanner.NonEmptyLines(res.Content.Text) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || isLocalIP(fields[0]) {
			continue
		}
		if slices.ContainsFunc(fields[1:], matchesCommonDomain) {
			rogue = append(rogue, line)
		}
	}

	res.Health = scanner.HealthOK
	res.Summary = "no rogue entries"
	if len(rogue) > 0 {
		res.Health = scanner.HealthCrit
		res.Summary = fmt.Sprintf("%d hijacked domain%s", len(rogue), plural(len(rogue), "", "s"))
		res.Anomalies = append(res.Anomalies, scanner.Anomaly{
			Severity: scanner.HealthCrit,
			Title:    "possible /etc/hosts hijack",
			Detail:   "A well-known domain is pinned to a non-local address.",
			Evidence: rogue,
			Artifact: "hosts",
		})
	}
	return res
}

func isLocalIP(ip string) bool {
	return ip == "::1" || ip == "0.0.0.0" || strings.HasPrefix(ip, "127.")
}

func matchesCommonDomain(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range commonDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// scanResolv lists the configured DNS servers.
func scanResolv(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := fileResult("resolv.conf", scanner.CatNetwork, env.Path("/etc/resolv.conf"))
	if res.Err != nil {
		setAbsent(&res)
		return res
	}
	var servers []string
	for _, line := range scanner.NonEmptyLines(res.Content.Text) {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	res.Health = scanner.HealthOK
	if len(servers) == 0 {
		res.Summary = "no nameservers configured"
	} else {
		res.Summary = fmt.Sprintf("%d nameserver%s: %s", len(servers), plural(len(servers), "", "s"), strings.Join(servers, ", "))
	}
	return res
}

// scanListeningPorts captures `ss -tulnp` and counts listening sockets.
func scanListeningPorts(ctx context.Context, env *scanner.Env) scanner.ScanResult {
	res := cmdSnapshot(ctx, env, "listening-ports", scanner.CatNetwork, "ss", "-tulnp")
	if res.Err != nil {
		return res
	}
	// The first line is a header; the rest are sockets.
	n := max(len(scanner.NonEmptyLines(res.Content.Text))-1, 0)
	res.Summary = fmt.Sprintf("%d listening port%s", n, plural(n, "", "s"))
	return res
}
