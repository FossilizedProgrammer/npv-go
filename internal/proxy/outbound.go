package proxy

import (
	"fmt"
	"npv-go/internal/npvs"
	"strings"
)

// Outbound is one xray outbound object, keyed by tag.
type Outbound map[string]any

// BuildOutbound turns a decoded config item into an xray outbound.
func BuildOutbound(s *npvs.Server, tag string) (Outbound, error) {
	switch s.Proto {
	case "vless":
		return vlessOutbound(s, tag)
	case "trojan":
		return trojanOutbound(s, tag)
	case "vmess":
		return vmessOutbound(s, tag)
	case "ss":
		return ssOutbound(s, tag)
	}
	return nil, fmt.Errorf("%s: protocol not supported", s.Proto)
}

func vlessOutbound(s *npvs.Server, tag string) (Outbound, error) {
	user := map[string]any{"id": s.Secret}
	if enc := s.Params["encryption"]; enc != "" {
		user["encryption"] = enc
	} else {
		user["encryption"] = "none"
	}
	if f := s.Params["flow"]; f != "" {
		user["flow"] = f
	}
	return Outbound{
		"protocol": "vless",
		"tag":      tag,
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": s.Host,
				"port":    s.Port,
				"users":   []any{user},
			}},
		},
		"streamSettings": streamSettings(s),
	}, nil
}

func trojanOutbound(s *npvs.Server, tag string) (Outbound, error) {
	server := map[string]any{"address": s.Host, "port": s.Port, "password": s.Secret}
	if f := s.Params["flow"]; f != "" {
		server["flow"] = f
	}
	return Outbound{
		"protocol": "trojan",
		"tag":      tag,
		"settings": map[string]any{
			"servers": []any{server},
		},
		"streamSettings": streamSettings(s),
	}, nil
}

func vmessOutbound(s *npvs.Server, tag string) (Outbound, error) {
	user := map[string]any{"id": s.Secret}
	if aid := s.Params["aid"]; aid != "" {
		user["alterId"] = atoi(aid)
	}
	if scy := s.Params["scy"]; scy != "" && scy != "auto" {
		user["security"] = scy
	}
	return Outbound{
		"protocol": "vmess",
		"tag":      tag,
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": s.Host,
				"port":    s.Port,
				"users":   []any{user},
			}},
		},
		"streamSettings": streamSettings(s),
	}, nil
}

func ssOutbound(s *npvs.Server, tag string) (Outbound, error) {
	method, password, ok := strings.Cut(s.Secret, ":")
	if !ok {
		return nil, fmt.Errorf("ss: bad userinfo %q", s.Secret)
	}
	return Outbound{
		"protocol": "shadowsocks",
		"tag":      tag,
		"settings": map[string]any{
			"servers": []any{map[string]any{
				"address":  s.Host,
				"port":     s.Port,
				"method":   method,
				"password": password,
			}},
		},
		"streamSettings": streamSettings(s),
	}, nil
}

// streamSettings maps the share-link transport parameters onto xray's
// streamSettings object.
func streamSettings(s *npvs.Server) map[string]any {
	p := s.Params
	network := orDefault(p["type"], "tcp")
	if network == "raw" {
		network = "tcp"
	}
	security := orDefault(p["security"], "none")

	stream := map[string]any{
		"network":  network,
		"security": security,
	}

	switch network {
	case "ws":
		ws := map[string]any{}
		if p["path"] != "" {
			ws["path"] = p["path"]
		}
		if p["host"] != "" {
			ws["host"] = p["host"]
		}
		stream["wsSettings"] = ws
	case "grpc":
		g := map[string]any{}
		if name := orDefault(p["serviceName"], p["path"]); name != "" {
			g["serviceName"] = name
		}
		if p["authority"] != "" {
			g["authority"] = p["authority"]
		}
		if p["mode"] == "multi" {
			g["multiMode"] = true
		}
		stream["grpcSettings"] = g
	case "kcp":
		k := map[string]any{}
		if seed := orDefault(p["seed"], p["path"]); seed != "" {
			k["seed"] = seed
		}
		if ht := p["headerType"]; ht != "" && ht != "none" {
			k["header"] = tcpHeader(s)
		}
		stream["kcpSettings"] = k
	case "httpupgrade":
		h := map[string]any{}
		if p["path"] != "" {
			h["path"] = p["path"]
		}
		if p["host"] != "" {
			h["host"] = p["host"]
		}
		stream["httpupgradeSettings"] = h
	case "xhttp", "http", "splithttp":
		h := map[string]any{}
		if p["path"] != "" {
			h["path"] = p["path"]
		}
		if p["host"] != "" {
			h["host"] = p["host"]
		}
		if p["mode"] != "" {
			h["mode"] = p["mode"]
		}
		if p["extra"] != "" {
			h["extra"] = rawJSON(p["extra"])
		}
		stream["xhttpSettings"] = h
	case "tcp":
		if ht := p["headerType"]; ht != "" && ht != "none" {
			stream["tcpSettings"] = map[string]any{"header": tcpHeader(s)}
		}
	}

	switch security {
	case "tls":
		tls := map[string]any{}
		if sni := orDefault(p["sni"], p["host"]); sni != "" {
			tls["serverName"] = sni
		}
		if p["fp"] != "" {
			tls["fingerprint"] = p["fp"]
		}
		if p["alpn"] != "" {
			tls["alpn"] = strings.Split(p["alpn"], ",")
		}
		if p["allowInsecure"] == "1" {
			tls["insecureSkipVerify"] = true
		}
		stream["tlsSettings"] = tls
	case "reality":
		reality := map[string]any{}
		if sni := p["sni"]; sni != "" {
			reality["serverName"] = sni
		}
		if p["fp"] != "" {
			reality["fingerprint"] = p["fp"]
		}
		if p["pbk"] != "" {
			reality["publicKey"] = p["pbk"]
		}
		if p["sid"] != "" {
			reality["shortId"] = p["sid"]
		}
		if p["spx"] != "" {
			reality["spiderX"] = p["spx"]
		}
		stream["realitySettings"] = reality
	}
	return stream
}

func tcpHeader(s *npvs.Server) map[string]any {
	header := map[string]any{"type": s.Params["headerType"]}
	request := map[string]any{}
	if s.Params["path"] != "" {
		request["path"] = strings.Split(s.Params["path"], ",")
	}
	if s.Params["host"] != "" {
		request["headers"] = map[string]any{"Host": s.Params["host"]}
	}
	if len(request) > 0 {
		header["request"] = request
	}
	return header
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
