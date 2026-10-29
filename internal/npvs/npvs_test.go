package npvs

import (
	"os"
	"testing"
)

// The sample export is a real gen2 (NPVS v5) bundle opened with the app's own
// whitebox custodian key, so it exercises the whole unwrap chain.
func TestDecodeGen2Sample(t *testing.T) {
	data, err := os.ReadFile("testdata/BOMB.npvs")
	if err != nil {
		t.Fatal(err)
	}
	if NeedsPassphrase(data) {
		t.Error("sample should unlock without a passphrase")
	}

	b, err := Decode(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if b.Format != "npvs-gen2" {
		t.Errorf("format = %q", b.Format)
	}
	if len(b.Links) != 31 {
		t.Fatalf("links = %d, want 31", len(b.Links))
	}
	if b.CreatorMessage == "" {
		t.Error("creator message not surfaced")
	}

	for _, link := range b.Links {
		s, err := ParseLink(link)
		if err != nil {
			t.Fatalf("ParseLink(%q): %v", link, err)
		}
		if s.Host == "" || s.Port == 0 {
			t.Errorf("bad target in %q", link)
		}
	}
}

func TestParseSSHKinds(t *testing.T) {
	s, err := ParseLink("ssh://u%40ser:p%40ss@example.com:22?remarks=box&sshConfigType=SSH-Direct&httpProxy=#root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != "ssh" || s.Host != "example.com" || s.Port != 22 {
		t.Errorf("got %+v", s)
	}
	if s.Params["sshUsername"] != "u@ser" || s.Params["sshPassword"] != "p@ss" {
		t.Errorf("credentials mangled: %q", s.Secret)
	}
	if s.Params["payload"] != "root@example.com" || s.Params["sshConfigType"] != "SSH-Direct" {
		t.Errorf("params mangled: %+v", s.Params)
	}
}
