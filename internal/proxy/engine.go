package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"npv-go/internal/npvs"

	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// Options configures the local proxy.
type Options struct {
	Server    *npvs.Server
	SocksAddr string
	HTTPAddr  string
	Loglevel  string
}

const primaryTag = "primary"

// Start brings up the local listeners for opt and returns a handle that closes
// them. SSH configs get a native tunnel, since xray has no SSH outbound.
func Start(ctx context.Context, opt Options) (io.Closer, error) {
	if opt.Server.Kind == "ssh" {
		return newSSHProxy(ctx, opt.Server, opt.SocksAddr)
	}
	return startXray(ctx, opt)
}

// Run starts the proxy for opt and blocks until ctx is cancelled.
func Run(ctx context.Context, opt Options, out io.Writer) error {
	closer, err := Start(ctx, opt)
	if err != nil {
		return err
	}
	defer closer.Close()

	printListeners(out, opt)
	<-ctx.Done()
	return nil
}

func printListeners(out io.Writer, opt Options) {
	if opt.Server.Kind == "ssh" {
		if opt.HTTPAddr != "" {
			fmt.Fprintln(out, "npv-go: ssh configs serve SOCKS5 only, --http is ignored")
		}
		fmt.Fprintf(out, "npv-go: %s (ssh) -> %s:%d\n", opt.Server.Remark, opt.Server.Host, opt.Server.Port)
		fmt.Fprintf(out, "  TCP forwarding only; the ssh command %q is unused\n", opt.Server.Params["payload"])
	} else {
		fmt.Fprintf(out, "npv-go: %s (%s) via %s\n", opt.Server.Remark, opt.Server.Proto, describe(opt.Server))
	}
	if opt.SocksAddr != "" {
		fmt.Fprintf(out, "  socks5:  socks5://%s\n", opt.SocksAddr)
	}
	if opt.HTTPAddr != "" {
		fmt.Fprintf(out, "  http:    http://%s\n", opt.HTTPAddr)
	}
	fmt.Fprintf(out, "  proxying all traffic received on those listeners.\n")
}

func startXray(ctx context.Context, opt Options) (io.Closer, error) {
	if opt.Loglevel == "none" {
		// Deprecation notices are emitted while the config is built, before the
		// instance's own log settings apply, so the global handler is muted too.
		clog.ReplaceWithSeverityLogger(clog.Severity_Unknown)
	}

	cfg, err := buildConfig(opt)
	if err != nil {
		return nil, err
	}

	pb, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}

	loaded, err := serial.LoadJSONConfig(strings.NewReader(string(pb)))
	if err != nil {
		return nil, fmt.Errorf("generated config rejected by xray: %w", err)
	}

	instance, err := core.New(loaded)
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, err
	}
	return instance, nil
}

func buildConfig(opt Options) (map[string]any, error) {
	primary, err := BuildOutbound(opt.Server, primaryTag)
	if err != nil {
		return nil, err
	}

	var inbounds []any
	if opt.SocksAddr != "" {
		host, port, err := splitAddr(opt.SocksAddr)
		if err != nil {
			return nil, fmt.Errorf("socks address: %w", err)
		}
		inbounds = append(inbounds, map[string]any{
			"port":     port,
			"protocol": "socks",
			"listen":   host,
			"tag":      "socks-in",
			"settings": map[string]any{
				"auth": "noauth",
				"udp":  true,
				"ip":   host,
			},
		})
	}
	if opt.HTTPAddr != "" {
		host, port, err := splitAddr(opt.HTTPAddr)
		if err != nil {
			return nil, fmt.Errorf("http address: %w", err)
		}
		inbounds = append(inbounds, map[string]any{
			"port":     port,
			"protocol": "http",
			"listen":   host,
			"tag":      "http-in",
			"settings": map[string]any{"timeout": 360},
		})
	}
	if len(inbounds) == 0 {
		return nil, fmt.Errorf("no listener requested")
	}

	loglevel := opt.Loglevel
	if loglevel == "" {
		loglevel = "warning"
	}

	cfg := map[string]any{
		"log":       map[string]any{"loglevel": loglevel},
		"inbounds":  inbounds,
		"outbounds": []any{primary},
	}
	return cfg, nil
}

func describe(s *npvs.Server) string {
	if s.Proto == "vless" && s.Params["security"] == "reality" {
		return "reality"
	}
	return orDefault(s.Params["type"], "tcp") + "/" + orDefault(s.Params["security"], "none")
}

// splitAddr separates a listen address into the host xray wants and a port
// number. IPv6 addresses arrive as [::1]:1080.
func splitAddr(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("expected host:port, got %q", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("bad port %q", portStr)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return host, port, nil
}

func rawJSON(s string) json.RawMessage {
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	return nil
}
