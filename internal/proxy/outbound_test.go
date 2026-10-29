package proxy

import (
	"encoding/json"
	"fmt"
	"testing"

	"npv-go/internal/npvs"
)

func server(t *testing.T, link string) *npvs.Server {
	t.Helper()
	s, err := npvs.ParseLink(link)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func streamOf(t *testing.T, ob Outbound) map[string]any {
	t.Helper()
	b, err := json.Marshal(ob)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Stream map[string]any `json:"streamSettings"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	return got.Stream
}

func TestOutboundReality(t *testing.T) {
	s := server(t, "vless://d4353076-3ec7-47dc-88b0-f21eb59fbfb8@193.160.140.159:8443?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&security=reality&sni=apple.com&type=tcp#x")
	ob, err := BuildOutbound(s, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if ob["protocol"] != "vless" || ob["tag"] != "primary" {
		t.Errorf("got %+v", ob)
	}
	st := streamOf(t, ob)
	if st["network"] != "tcp" || st["security"] != "reality" {
		t.Errorf("stream = %+v", st)
	}
	reality, ok := st["realitySettings"].(map[string]any)
	if !ok {
		t.Fatalf("no realitySettings in %+v", st)
	}
	if reality["publicKey"] != "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc" || reality["serverName"] != "apple.com" || reality["fingerprint"] != "chrome" {
		t.Errorf("reality = %+v", reality)
	}
}

func TestOutboundWebsocketTLS(t *testing.T) {
	s := server(t, "trojan://MiTiVPN@146.75.57.120:443?alpn=http%2F1.1&fp=chrome&host=mitivpn.ac.ir&path=%2Fws&security=tls&sni=firefox.com&type=ws#x")
	ob, err := BuildOutbound(s, "primary")
	if err != nil {
		t.Fatal(err)
	}
	st := streamOf(t, ob)
	if st["network"] != "ws" || st["security"] != "tls" {
		t.Errorf("stream = %+v", st)
	}
	ws := st["wsSettings"].(map[string]any)
	if ws["path"] != "/ws" {
		t.Errorf("ws path = %v", ws["path"])
	}
	if ws["host"] != "mitivpn.ac.ir" {
		t.Errorf("ws host = %v", ws["host"])
	}
	tlsSet := st["tlsSettings"].(map[string]any)
	if tlsSet["serverName"] != "firefox.com" {
		t.Errorf("sni = %v", tlsSet["serverName"])
	}
	alpn, _ := json.Marshal(tlsSet["alpn"])
	if string(alpn) != `["http/1.1"]` {
		t.Errorf("alpn = %s", alpn)
	}
}

func TestOutboundShadowsocks(t *testing.T) {
	s := server(t, "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpxSm85Z1RlczduSTNBbHhp@20.164.216.117:443#x")
	ob, err := BuildOutbound(s, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if ob["protocol"] != "shadowsocks" {
		t.Fatalf("protocol = %v", ob["protocol"])
	}
	settings := ob["settings"].(map[string]any)
	srv := settings["servers"].([]any)[0].(map[string]any)
	if srv["method"] != "chacha20-ietf-poly1305" || srv["password"] != "qJo9gTes7nI3Alxi" {
		t.Errorf("server = %+v", srv)
	}
	if srv["address"] != "20.164.216.117" || fmt.Sprint(srv["port"]) != "443" {
		t.Errorf("target = %+v", srv)
	}
}

func TestSSHIgnoredByXray(t *testing.T) {
	s := server(t, "ssh://u:p@example.com:22?remarks=box&sshConfigType=SSH-Direct#root@example.com")
	if s.Kind != "ssh" {
		t.Fatalf("kind = %s", s.Kind)
	}
	if _, err := BuildOutbound(s, "primary"); err == nil {
		t.Fatal("ssh must not be handed to xray")
	}
}
