package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"npv-go/internal/npvs"

	"golang.org/x/crypto/ssh"
)

// sshProxy is a local SOCKS5 proxy whose connections are forwarded through SSH
// direct-tcpip channels. xray has no SSH outbound, so this shape is native.
type sshProxy struct {
	client sshCloser
	ln     net.Listener
	cancel context.CancelFunc
	done   chan struct{}
}

type sshCloser interface {
	io.Closer
	Dial(n, addr string) (net.Conn, error)
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
}

func newSSHProxy(ctx context.Context, s *npvs.Server, socksAddr string) (*sshProxy, error) {
	// The export only carries host, port, credentials and the config type, so
	// anything that needs a TLS wrap, an upstream proxy or payload injection
	// cannot be reconstructed from it.
	if kind := s.Params["sshConfigType"]; kind != "" && kind != "SSH-Direct" {
		return nil, fmt.Errorf("ssh config type %q needs fields the .npvs export does not carry; only SSH-Direct is possible", kind)
	}

	user, pass, _ := strings.Cut(s.Secret, ":")
	client, err := ssh.Dial("tcp", net.JoinHostPort(s.Host, fmt.Sprint(s.Port)), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh handshake with %s:%d: %w", s.Host, s.Port, err)
	}

	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		client.Close()
		return nil, err
	}

	runCtx, cancel := context.WithCancel(ctx)
	p := &sshProxy{client: client, ln: ln, cancel: cancel, done: make(chan struct{})}

	go keepalive(runCtx, client)
	go func() {
		defer close(p.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS(client, conn)
		}
	}()
	return p, nil
}

func (p *sshProxy) Close() error {
	p.cancel()
	p.ln.Close()
	err := p.client.Close()
	<-p.done
	return err
}

func keepalive(ctx context.Context, client *ssh.Client) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				return
			}
		}
	}
}

func serveSOCKS(client *ssh.Client, conn net.Conn) {
	defer conn.Close()

	dst, err := socksHandshake(conn)
	if err != nil {
		return
	}

	up, err := client.Dial("tcp", dst)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()

	// Success reply, with a zeroed bind address.
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(up, conn)
		closeWrite(up)
	}()
	_, _ = io.Copy(conn, up)
}

// socksHandshake reads a SOCKS5 greeting and CONNECT request, returning the
// "host:port" the client wants reached.
func socksHandshake(conn net.Conn) (string, error) {
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		return "", err
	}
	if greet[0] != 0x05 {
		return "", fmt.Errorf("not socks5")
	}
	methods := make([]byte, greet[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // no auth
		return "", err
	}

	head := make([]byte, 5)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[1] != 0x01 { // CONNECT only
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("unsupported socks command")
	}

	var host string
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", fmt.Errorf("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(portBuf))), nil
}

// closeWrite half-closes the channel so the remote sees EOF, when it supports it.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
