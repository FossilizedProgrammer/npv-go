package proxy

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"npv-go/internal/npvs"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// accept asks xray itself whether it would take the generated config. Building
// the JSON is not enough: a wrong field name is only reported here.
func accept(t *testing.T, link string) {
	t.Helper()
	s, err := npvs.ParseLink(link)
	if err != nil {
		t.Fatalf("parse %q: %v", link, err)
	}
	cfg, err := buildConfig(Options{Server: s, SocksAddr: "127.0.0.1:20000", HTTPAddr: "127.0.0.1:20001", Loglevel: "none"})
	if err != nil {
		t.Fatalf("build %q: %v", link, err)
	}
	pb, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := serial.LoadJSONConfig(strings.NewReader(string(pb)))
	if err != nil {
		t.Fatalf("xray rejected %s: %v\n%s", s.Proto, err, pb)
	}
	instance, err := core.New(loaded)
	if err != nil {
		t.Fatalf("xray could not build %s: %v\n%s", s.Proto, err, pb)
	}
	_ = instance
}

func TestGeneratedConfigsAcceptedByXray(t *testing.T) {
	links := []string{
		"vless://d4353076-3ec7-47dc-88b0-f21eb59fbfb8@193.160.140.159:8443?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&security=reality&sni=apple.com&type=tcp#x",
		"vless://d4353076-3ec7-47dc-88b0-f21eb59fbfb8@193.160.140.159:443?encryption=none&host=bbb.com&path=%2Fws&security=tls&sni=aaa.com&type=ws#x",
		"vless://d4353076-3ec7-47dc-88b0-f21eb59fbfb8@193.160.140.159:443?encryption=none&mode=auto&path=%2Fxhttp&security=tls&sni=aaa.com&type=xhttp#x",
		"vless://d4353076-3ec7-47dc-88b0-f21eb59fbfb8@193.160.140.159:443?encryption=none&path=svc&security=tls&sni=aaa.com&type=grpc#x",
		"vless://d4353076-3ec7-47dc-88b0-f21eb59fbfb8@193.160.140.159:443?encryption=none&seed=abc&headerType=srtp&security=none&type=kcp#x",
		"vless://d4353076-3ec7-47dc-88b0-f21eb59fbfb8@193.160.140.159:443?encryption=none&host=bbb.com&path=%2Fup&security=tls&type=httpupgrade#x",
		"vless://d4353076-3ec7-47dc-88b0-f21eb59fbfb8@193.160.140.159:443?encryption=none&host=bbb.com&path=%2F&headerType=http&security=none&type=tcp#x",
		"trojan://MiTiVPN@146.75.57.120:443?alpn=http%2F1.1&fp=chrome&host=mitivpn.ac.ir&path=%2Fws&security=tls&sni=firefox.com&type=ws#x",
		"trojan://password1@146.75.57.120:443?security=tls&sni=firefox.com&type=tcp#x",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpxSm85Z1RlczduSTNBbHhp@20.164.216.117:443#x",
		vmessLink(t, map[string]string{"net": "ws", "tls": "tls", "host": "bbb.com", "path": "/ws", "sni": "aaa.com", "alpn": "h2,http/1.1"}),
		vmessLink(t, map[string]string{"net": "grpc", "tls": "tls", "type": "multi", "host": "auth.example.com", "path": "svc", "sni": "aaa.com"}),
		vmessLink(t, map[string]string{"net": "kcp", "type": "srtp", "seed": "abc"}),
		vmessLink(t, map[string]string{"net": "tcp", "type": "http", "host": "bbb.com", "path": "/x"}),
		vmessLink(t, map[string]string{}),
	}
	for _, link := range links {
		accept(t, link)
	}
}

// vmessLink builds a base64 vmess share link, the shape this app exports.
func vmessLink(t *testing.T, extra map[string]string) string {
	t.Helper()
	obj := map[string]string{
		"v": "2", "ps": "x", "add": "193.160.140.159", "port": "443",
		"id": "d4353076-3ec7-47dc-88b0-f21eb59fbfb8", "aid": "0", "scy": "auto",
	}
	for k, v := range extra {
		obj[k] = v
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

// TestEverySampleConfigIsAccepted runs the whole bundled export through xray's
// own config parser, which is what caught the trojan mapping mistake.
func TestEverySampleConfigIsAccepted(t *testing.T) {
	path := filepath.Join("..", "..", "BOMB.npvs")
	data, err := os.ReadFile(path)
	if err != nil {
		skipIfNoSample(t, err)
	}

	bundle, err := npvs.Decode(data, "")
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}

	var checked, skipped int
	for _, link := range bundle.Links {
		s, err := npvs.ParseLink(link)
		if err != nil || s.Kind == "ssh" {
			skipped++
			continue
		}
		checked++
		accept(t, link)
	}
	if checked == 0 {
		t.Fatalf("no v2ray config found in %s (%d links)", path, len(bundle.Links))
	}
	t.Logf("xray accepted %d configs, skipped %d non-v2ray or unparsable lines", checked, skipped)
}

func skipIfNoSample(t *testing.T, err error) {
	t.Helper()
	if os.IsNotExist(err) {
		t.Skip("sample export not present")
	}
	t.Fatal(err)
}
