package npvs

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const (
	npvOpenMarker   = "NPVO1"
	npvSubMarker    = "NPVTSUB1"
	npvLegacyMarker = "NPVT1"
	npvOpenMaxSize  = 8 << 20
)

type npvOpenEnvelope struct {
	Configs []any `json:"configs"`
}

func isNpvOpenEnvelope(b []byte) bool {
	head := strings.TrimLeft(string(b), " \t\r\n")
	return strings.HasPrefix(head, npvOpenMarker)
}

func npvLegacyMarkerOf(b []byte) string {
	head := strings.TrimLeft(string(b), " \t\r\n")
	switch {
	case strings.HasPrefix(head, npvSubMarker):
		return npvSubMarker
	case strings.HasPrefix(head, npvLegacyMarker):
		return npvLegacyMarker
	}
	return ""
}

func npvOpenStripMarker(s, marker string) string {
	s = strings.ReplaceAll(s, marker+"\n", "")
	return strings.ReplaceAll(s, marker, "")
}

func parseNpvOpenEnvelope(b []byte) (*npvOpenEnvelope, error) {
	if len(b) > npvOpenMaxSize {
		return nil, fmt.Errorf("npvs open: file too large: %d bytes", len(b))
	}

	body := npvOpenStripMarker(string(b), npvOpenMarker)
	if strings.TrimSpace(body) == "" {
		return nil, errors.New("npvs open: empty payload after marker")
	}

	var env npvOpenEnvelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		return nil, fmt.Errorf("npvs open: payload is not a config list: %w", err)
	}
	if len(env.Configs) == 0 {
		return nil, errors.New("npvs open: payload has no configs")
	}
	return &env, nil
}

func npvOpenDecodeSentinels(v any) any {
	switch t := v.(type) {
	case string:
		return decodeNpvSentinels(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = npvOpenDecodeSentinels(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = npvOpenDecodeSentinels(x)
		}
		return out
	default:
		return v
	}
}

func npvOpenLinks(env *npvOpenEnvelope) []string {
	links := make([]string, 0, len(env.Configs))
	for _, cfg := range env.Configs {
		links = append(links, npvGen2Link(npvOpenDecodeSentinels(cfg)))
	}
	return links
}

func decodeOpen(data []byte) (*Bundle, error) {
	env, err := parseNpvOpenEnvelope(data)
	if err != nil {
		return nil, err
	}

	links := splitLinks(strings.Join(npvOpenLinks(env), "\n"))
	if len(links) == 0 {
		return nil, errors.New("npvs open: container holds no share links")
	}

	return &Bundle{Format: "npvs-open", Links: links}, nil
}

// Server is one decoded config item, ready to be turned into an outbound.
type Server struct {
	Index  int
	Kind   string // "v2ray" or "ssh"
	Proto  string // vless, trojan, ss, vmess, ssh
	Host   string
	Port   int
	Secret string
	Params map[string]string
	Remark string
	Link   string
}

func ParseLink(raw string) (*Server, error) {
	s, err := parseShareURI(raw)
	if err != nil {
		return nil, err
	}
	kind := "v2ray"
	if s.Protocol == "ssh" {
		kind = "ssh"
	}
	return &Server{
		Kind:   kind,
		Proto:  s.Protocol,
		Host:   s.Host,
		Port:   s.Port,
		Secret: s.Secret,
		Params: s.Params,
		Remark: s.Remark,
		Link:   raw,
	}, nil
}

type npvShareURI struct {
	Protocol string
	Host     string
	Port     int
	Secret   string
	Params   map[string]string
	Remark   string
}

func parseShareURI(raw string) (*npvShareURI, error) {
	raw = strings.TrimSpace(raw)
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, fmt.Errorf("share uri: missing scheme: %q", raw)
	}

	switch scheme {
	case "vless", "trojan":
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("share uri: %s: %w", scheme, err)
		}
		secret := ""
		if u.User != nil {
			secret = u.User.Username()
		}
		if secret == "" {
			return nil, fmt.Errorf("share uri: %s: missing secret", scheme)
		}
		if u.Hostname() == "" {
			return nil, fmt.Errorf("share uri: %s: missing host", scheme)
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("share uri: %s: bad port %q", scheme, u.Port())
		}
		return &npvShareURI{
			Protocol: scheme,
			Host:     u.Hostname(),
			Port:     port,
			Secret:   secret,
			Params:   npvQueryMap(u),
			Remark:   npvFragment(u),
		}, nil

	case "vmess":
		payload, _, _ := strings.Cut(rest, "#")
		dec, err := npvBase64Decode(payload)
		if err != nil {
			return nil, fmt.Errorf("share uri: vmess: %w", err)
		}
		var obj map[string]any
		if err := json.Unmarshal(dec, &obj); err != nil {
			return nil, fmt.Errorf("share uri: vmess: bad json: %w", err)
		}
		params := make(map[string]string, len(obj))
		for k, v := range obj {
			params[k] = npvGen2Text(v)
		}
		if params["add"] == "" || params["id"] == "" {
			return nil, errors.New("share uri: vmess: missing add/id")
		}
		port := npvGen2Int(params["port"])
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("share uri: vmess: bad port %d", port)
		}
		normalizeVMess(params)
		return &npvShareURI{
			Protocol: "vmess",
			Host:     params["add"],
			Port:     port,
			Secret:   params["id"],
			Params:   params,
			Remark:   params["ps"],
		}, nil

	case "ss":
		body, frag, _ := strings.Cut(rest, "#")
		userinfo, hostPort, ok := strings.Cut(body, "@")
		if !ok {
			dec, err := npvBase64Decode(body)
			if err != nil {
				return nil, fmt.Errorf("share uri: ss: %w", err)
			}
			userinfo, hostPort, ok = strings.Cut(string(dec), "@")
			if !ok {
				return nil, errors.New("share uri: ss: malformed payload")
			}
		} else if dec, err := npvBase64Decode(userinfo); err == nil {
			userinfo = string(dec)
		}
		if !strings.Contains(userinfo, ":") {
			return nil, errors.New("share uri: ss: missing method:password")
		}
		host, portStr, ok := strings.Cut(hostPort, ":")
		if !ok {
			return nil, fmt.Errorf("share uri: ss: missing port in %q", hostPort)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("share uri: ss: bad port %q", portStr)
		}
		return &npvShareURI{
			Protocol: "ss",
			Host:     host,
			Port:     port,
			Secret:   userinfo,
			Params:   map[string]string{},
			Remark:   npvUrlUnescape(frag),
		}, nil

	case "ssh":
		body, payload, _ := strings.Cut(rest, "#")
		target, rawQuery, _ := strings.Cut(body, "?")
		userinfo, hostPort, ok := strings.Cut(target, "@")
		if !ok {
			return nil, errors.New("share uri: ssh: missing userinfo@host")
		}
		user, pass, _ := strings.Cut(userinfo, ":")
		user, pass = npvUrlUnescape(user), npvUrlUnescape(pass)

		host, portStr, ok := strings.Cut(hostPort, ":")
		if !ok {
			return nil, fmt.Errorf("share uri: ssh: missing port in %q", hostPort)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("share uri: ssh: bad port %q", portStr)
		}

		params := map[string]string{}
		if q, err := url.ParseQuery(rawQuery); err == nil {
			for k, v := range q {
				if len(v) > 0 {
					params[k] = v[0]
				}
			}
		}
		params["payload"] = payload
		params["sshUsername"] = user
		params["sshPassword"] = pass

		return &npvShareURI{
			Protocol: "ssh",
			Host:     host,
			Port:     port,
			Secret:   user + ":" + pass,
			Params:   params,
			Remark:   params["remarks"],
		}, nil
	}

	return nil, fmt.Errorf("share uri: unsupported protocol %q", scheme)
}

// normalizeVMess rewrites the vmess JSON keys onto the transport parameter
// names the outbound builder reads. vmess calls the transport "net" and uses
// "type" for the header, which is the opposite of the query parameters carried
// by vless and trojan links.
func normalizeVMess(p map[string]string) {
	network := strings.ToLower(strings.TrimSpace(npvGen2Or(p["net"], "tcp")))
	switch network {
	case "raw":
		network = "tcp"
	case "h2":
		network = "http"
	}

	switch network {
	case "grpc":
		p["serviceName"] = npvGen2Or(p["serviceName"], p["path"])
		p["authority"] = npvGen2Or(p["authority"], p["host"])
		p["mode"] = npvGen2Or(p["mode"], p["type"])
	default:
		if ht := p["type"]; ht != "" && ht != "none" {
			p["headerType"] = npvGen2Or(p["headerType"], ht)
		}
	}
	p["type"] = network

	if p["security"] == "" {
		switch {
		case p["pbk"] != "":
			p["security"] = "reality"
		case strings.ToLower(p["tls"]) == "tls":
			p["security"] = "tls"
		default:
			p["security"] = "none"
		}
	}
	if p["insecure"] == "1" {
		p["allowInsecure"] = "1"
	}
}

func npvQueryMap(u *url.URL) map[string]string {
	q := u.Query()
	out := make(map[string]string, len(q))
	for k, v := range q {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func npvFragment(u *url.URL) string {
	return npvUrlUnescape(u.Fragment)
}

func npvUrlUnescape(s string) string {
	out, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return out
}

func npvBase64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if dec, err := enc.DecodeString(s); err == nil {
			return dec, nil
		}
	}
	return nil, errors.New("invalid base64")
}
