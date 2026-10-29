package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"npv-go/internal/npvs"
	"npv-go/internal/proxy"
)

const usage = `npv-go - use NPV Tunnel (.npvs) exports as a local proxy

  npv-go list    [-check] [-all] [-json] [-url u] [-timeout d] [-samples n] [-jobs n] [-pass p] <file>
  npv-go connect [-socks addr] [-http addr] [-log level] [-url u] [-timeout d] [-samples n] [-jobs n] [-pass p] <file>
  npv-go serve   [-s N] [-socks addr] [-http addr] [-log level] <file>
  npv-go config  [-s N]             [-pass p] <file>
  npv-go decode  [-o out]           [-pass p] <file>

Pass flags before the file name. -s picks a config by its 1-based number or by
a substring of its remark; run "list" first to see them.
-socks and -http take a port (1080), a host:port pair (127.0.0.1:1080) or an
empty value to disable that listener. A bare port binds loopback only.
list -check pushes real traffic through every config and prints only the ones
that answer, fastest first (-all also lists the dead ones).
list -json writes one JSON object instead of the table: every config with its
verdict, answered ones first and fastest first.
connect does that probe on its own and then serves the fastest config that
answered, so there is nothing to pick by hand.
A plain text file of share links works wherever a .npvs file does.
`

type globals struct {
	pass     string
	socks    string
	http     string
	loglevel string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}

	var g globals
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	fs.StringVar(&g.pass, "pass", "", "passphrase, if the export is passphrase locked")
	fs.StringVar(&g.socks, "socks", "127.0.0.1:1080", "SOCKS5 listen address: port, host:port, or empty to disable")
	fs.StringVar(&g.http, "http", "127.0.0.1:8080", "HTTP proxy listen address: port, host:port, or empty to disable")
	fs.StringVar(&g.loglevel, "log", "", "xray log level: error, warning, info, none; connect defaults to none")
	selected := fs.String("s", "1", "config to use: number or remark substring")
	doCheck := fs.Bool("check", false, "probe each config through a real tunnel (list)")
	all := fs.Bool("all", false, "with -check, also show the configs that do not work")
	jsonOut := fs.Bool("json", false, "print list output as a single JSON object (list)")
	probeURL := fs.String("url", "", "with -check, probe target URL (default: a reachable generate_204)")
	timeout := fs.Duration("timeout", 10*time.Second, "with -check, per-request timeout")
	samples := fs.Int("samples", 3, "with -check, requests per config; the median of them is reported")
	jobs := fs.Int("jobs", 3, "with -check, configs probed at the same time")
	Out := fs.String("o", "", "write decoded links here instead of stdout (decode)")

	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	path := fs.Arg(0)
	if path == "" {
		fmt.Print(usage)
		os.Exit(2)
	}

	if os.Args[1] == "serve" || os.Args[1] == "connect" {
		var err error
		if g.socks, err = listenAddr(g.socks); err != nil {
			fail(fmt.Errorf("-socks: %w", err))
		}
		if g.http, err = listenAddr(g.http); err != nil {
			fail(fmt.Errorf("-http: %w", err))
		}
		if g.socks == "" && g.http == "" {
			fail(errors.New("both -socks and -http are disabled, there would be nothing to listen on"))
		}
		// Report a busy address before the work, not after it.
		if err := listenersUsable(g); err != nil {
			fail(err)
		}
		if g.loglevel == "" {
			// connect mutes xray by default: its probe instances log through the
			// same process-wide logger, so a dial still failing when the serving
			// instance starts looks like the chosen config is broken.
			g.loglevel = "warning"
			if os.Args[1] == "connect" {
				g.loglevel = "none"
			}
		}
	}

	servers, bundle, err := load(path, g.pass)
	if err != nil {
		fail(err)
	}

	spec := func() proxy.CheckSpec {
		return proxy.CheckSpec{Timeout: *timeout, Samples: *samples, Jobs: *jobs, URL: *probeURL}
	}

	switch os.Args[1] {
	case "list":
		if *jsonOut {
			var results []proxy.CheckResult
			if *doCheck {
				ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
				defer stop()
				rs, err := proxy.Check(ctx, servers, spec())
				if err != nil {
					fail(err)
				}
				results = rs
			}
			printJSONList(os.Stdout, servers, bundle, results)
			return
		}
		if !*doCheck {
			listServers(os.Stdout, servers, bundle)
			return
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		results, err := proxy.Check(ctx, servers, spec())
		if err != nil {
			fail(err)
		}
		printChecked(os.Stdout, results, *all)
	case "connect":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		results, err := proxy.Check(ctx, servers, spec())
		if err != nil {
			fail(err)
		}
		working := workingResults(results)
		if len(working) == 0 {
			fail(fmt.Errorf("connect: none of the %d configs answered; try \"list -check -all\" for the reasons", len(results)))
		}
		short := working
		if len(short) > 3 {
			short = short[:3]
		}
		fmt.Fprintf(os.Stdout, "npv-go: %d of %d configs answered, connecting to the fastest\n\n", len(working), len(results))
		printCheckedHeader(os.Stdout)
		printCheckedRows(os.Stdout, short)
		fmt.Fprintln(os.Stdout)
		// A probe instance is closed, but xray logs through one process-wide
		// logger and a dial still in flight would otherwise print under the
		// serving instance's log level. Let those stragglers finish first.
		time.Sleep(2 * time.Second)
		serve(working[0].Server, g)
	case "decode":
		text := bundle.Text()
		if *Out != "" {
			if err := os.WriteFile(*Out, []byte(text), 0o600); err != nil {
				fail(err)
			}
			fmt.Fprintf(os.Stderr, "npv-go: wrote %s\n", *Out)
			return
		}
		fmt.Println(text)
	case "serve", "config":
		srv, err := pick(servers, *selected)
		if err != nil {
			fail(err)
		}
		if os.Args[1] == "config" {
			if srv.Kind == "ssh" {
				fail(errors.New("config: ssh configs are served natively, there is no xray config for them"))
			}
			ob, err := proxy.BuildOutbound(srv, "primary")
			if err != nil {
				fail(err)
			}
			b, err := json.MarshalIndent(ob, "", "  ")
			if err != nil {
				fail(err)
			}
			fmt.Println(string(b))
			return
		}
		serve(srv, g)
	default:
		fmt.Printf("unknown command %q\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(2)
	}
}

// listenAddr accepts "1080", "127.0.0.1:1080" or "" (disabled) and returns a
// host:port pair. A bare port stays on loopback; use 0.0.0.0:port to expose it.
func listenAddr(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	host, port := "", v
	if h, p, err := net.SplitHostPort(v); err == nil {
		host, port = h, p
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("bad address %q, expected a port like 1080 or host:port like 127.0.0.1:1080", v)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

// listenersUsable reports a listener address that cannot be bound, so the user
// learns it before a long probe instead of after.
func listenersUsable(g globals) error {
	for _, l := range []struct{ flag, addr string }{{"socks", g.socks}, {"http", g.http}} {
		if l.addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			if errors.Is(err, syscall.EADDRINUSE) {
				return fmt.Errorf("-%s address %s is already in use; pick another port with -%s or stop whatever holds it", l.flag, l.addr, l.flag)
			}
			return fmt.Errorf("-%s address %s: %w", l.flag, l.addr, err)
		}
		ln.Close()
	}
	return nil
}

func serve(srv *npvs.Server, g globals) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := proxy.Run(ctx, proxy.Options{
		Server:    srv,
		SocksAddr: g.socks,
		HTTPAddr:  g.http,
		Loglevel:  g.loglevel,
	}, os.Stdout)
	if err != nil {
		fail(err)
	}
}

// load reads an export, or a plain file of share links, into config items.
func load(path, passphrase string) ([]*npvs.Server, *npvs.Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	bundle, err := npvs.Decode(data, passphrase)
	if err != nil {
		if links := plainLinks(data); len(links) > 0 {
			bundle = &npvs.Bundle{Format: "share links", Links: links}
		} else {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
	}

	servers := make([]*npvs.Server, 0, len(bundle.Links))
	for i, link := range bundle.Links {
		srv, err := npvs.ParseLink(link)
		if err != nil {
			fmt.Fprintf(os.Stderr, "npv-go: skipping entry %d: %v\n", i+1, err)
			continue
		}
		srv.Index = i + 1
		if srv.Remark == "" {
			srv.Remark = fmt.Sprintf("%s:%d", srv.Host, srv.Port)
		}
		servers = append(servers, srv)
	}
	if len(servers) == 0 {
		return nil, nil, fmt.Errorf("%s: no usable configs", path)
	}
	return servers, bundle, nil
}

// plainLinks accepts a text file that is already a list of share links.
func plainLinks(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "", strings.HasPrefix(line, "//"), !strings.Contains(line, "://"):
			continue
		}
		out = append(out, line)
	}
	return out
}

// jsonListServer is one config item as the app reads it.
type jsonListServer struct {
	Index     int    `json:"index"`
	Remark    string `json:"remark"`
	Proto     string `json:"proto"`
	Kind      string `json:"kind"`
	Transport string `json:"transport"`
	OK        bool   `json:"ok"`
	MedianMs  int64  `json:"medianMs,omitempty"`
	Error     string `json:"error,omitempty"`
}

type jsonList struct {
	CreatorMessage string           `json:"creatorMessage,omitempty"`
	Checked        bool             `json:"checked"`
	Total          int              `json:"total"`
	Answered       int              `json:"answered"`
	Servers        []jsonListServer `json:"servers"`
}

// printJSONList writes the inventory as one JSON object. When the caller
// probed, results order the list (answered configs first, fastest first) and
// each item carries its verdict; without a probe, checked is false and no item
// claims ok.
func printJSONList(out *os.File, servers []*npvs.Server, bundle *npvs.Bundle, results []proxy.CheckResult) {
	report := jsonList{Checked: len(results) > 0, Total: len(servers)}
	if bundle.CreatorMessage != "" {
		report.CreatorMessage = firstLine(bundle.CreatorMessage)
	}

	item := func(s *npvs.Server) jsonListServer {
		return jsonListServer{
			Index: s.Index, Remark: s.Remark, Proto: s.Proto,
			Kind: s.Kind, Transport: transport(s),
		}
	}

	if report.Checked {
		for _, r := range results {
			entry := item(r.Server)
			if r.Err != nil {
				entry.Error = r.Err.Error()
			} else {
				entry.OK = true
				entry.MedianMs = r.Median.Milliseconds()
				report.Answered++
			}
			report.Servers = append(report.Servers, entry)
		}
	} else {
		for _, s := range servers {
			report.Servers = append(report.Servers, item(s))
		}
	}

	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(report); err != nil {
		fail(err)
	}
}

func listServers(out *os.File, servers []*npvs.Server, bundle *npvs.Bundle) {
	if bundle.CreatorMessage != "" {
		fmt.Fprintf(out, "creator message: %s\n\n", firstLine(bundle.CreatorMessage))
	}
	fmt.Fprintf(out, "%-4s %-8s %-7s %-40s %s\n", "#", "proto", "kind", "server", "transport")
	for _, s := range servers {
		fmt.Fprintf(out, "%-4d %-8s %-7s %-40s %s\n", s.Index, s.Proto, s.Kind, truncate(s.Remark, 40), transport(s))
	}
}

// workingResults returns the probes that answered, fastest first, as Check
// already ordered them.
func workingResults(results []proxy.CheckResult) []*proxy.CheckResult {
	var working []*proxy.CheckResult
	for i := range results {
		if results[i].OK() {
			working = append(working, &results[i])
		}
	}
	return working
}

func printCheckedHeader(out *os.File) {
	fmt.Fprintf(out, "%-5s %-4s %-8s %-14s %-32s %s\n", "rank", "#", "proto", "transport", "server", "median")
}

func printCheckedRows(out *os.File, working []*proxy.CheckResult) {
	for i, r := range working {
		fmt.Fprintf(out, "%-5d %-4d %-8s %-14s %-32s %s\n",
			i+1, r.Server.Index, r.Server.Proto, transport(r.Server),
			truncate(r.Server.Remark, 32), r.Median.Round(10*time.Millisecond))
	}
}

// printChecked lists the configs that answered, fastest first.
func printChecked(out *os.File, results []proxy.CheckResult, includeDead bool) {
	working := workingResults(results)

	if len(working) == 0 {
		fmt.Fprintln(out, "no config answered")
	} else {
		fmt.Fprintf(out, "%d of %d configs answered, fastest first\n\n", len(working), len(results))
		printCheckedHeader(out)
		printCheckedRows(out, working)
	}

	if !includeDead {
		return
	}
	fmt.Println()
	for _, r := range results {
		if r.OK() {
			continue
		}
		fmt.Fprintf(out, "%-5s %-4d %-8s %-14s %-32s %v\n",
			"-", r.Server.Index, r.Server.Proto, transport(r.Server), truncate(r.Server.Remark, 32), r.Err)
	}
}

func pick(servers []*npvs.Server, sel string) (*npvs.Server, error) {
	sel = strings.TrimSpace(sel)
	if n, err := strconv.Atoi(sel); err == nil {
		for _, s := range servers {
			if s.Index == n {
				return s, nil
			}
		}
		return nil, fmt.Errorf("no config numbered %d", n)
	}
	var matches []*npvs.Server
	for _, s := range servers {
		if strings.Contains(strings.ToLower(s.Remark), strings.ToLower(sel)) {
			matches = append(matches, s)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, fmt.Errorf("no config matches %q", sel)
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, fmt.Sprintf("%d:%s", m.Index, m.Remark))
		}
		return nil, fmt.Errorf("%q matches %d configs (%s), pick by number", sel, len(matches), strings.Join(names, ", "))
	}
}

func transport(s *npvs.Server) string {
	if s.Kind == "ssh" {
		return "ssh/" + s.Params["sshConfigType"]
	}
	netw := orEmpty(s.Params["type"], "tcp")
	sec := orEmpty(s.Params["security"], "none")
	if sec == "reality" {
		return netw + "/reality"
	}
	return netw + "/" + sec
}

func orEmpty(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + "..."
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "npv-go: %v\n", err)
	os.Exit(1)
}
