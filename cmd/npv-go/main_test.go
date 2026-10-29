package main

import (
	"net"
	"testing"
)

func TestListenAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"1080", "127.0.0.1:1080"},
		{"127.0.0.1:1080", "127.0.0.1:1080"},
		{":1080", "127.0.0.1:1080"},
		{"0.0.0.0:1080", "0.0.0.0:1080"},
		{"[::1]:1080", "[::1]:1080"},
	}
	for _, c := range cases {
		got, err := listenAddr(c.in)
		if err != nil {
			t.Errorf("listenAddr(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("listenAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	for _, bad := range []string{"abc", "0", "65536", "1.2.3.4:notaport", "socks5://127.0.0.1"} {
		if got, err := listenAddr(bad); err == nil {
			t.Errorf("listenAddr(%q) = %q, want an error", bad, got)
		}
	}
}

func TestListenersUsableReportsBusyAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	err = listenersUsable(globals{socks: ln.Addr().String(), http: "127.0.0.1:0"})
	if err == nil {
		t.Fatal("a busy address must be reported")
	}
	t.Log(err)
}
