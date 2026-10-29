package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"npv-go/internal/npvs"

	"golang.org/x/net/proxy"
)

// CheckSpec controls how aggressively the config items are probed.
type CheckSpec struct {
	Timeout time.Duration
	Samples int
	Jobs    int
	URL     string // probe target; empty picks a reachable one
}

// CheckResult is the outcome of probing one config item.
type CheckResult struct {
	Server *npvs.Server
	Median time.Duration
	Err    error
}

func (c CheckResult) OK() bool { return c.Err == nil }

// probeTargets are tried directly, without a proxy, to find a URL worth
// measuring through the tunnel.
var probeTargets = []string{
	"https://www.gstatic.com/generate_204",
	"https://cp.cloudflare.com/generate_204",
	"https://www.google.com/generate_204",
	"https://one.one.one.one/generate_204",
}

// Check starts a listener for every config item, pushes real traffic through
// it, and reports which ones work, fastest first.
func Check(ctx context.Context, servers []*npvs.Server, spec CheckSpec) ([]CheckResult, error) {
	if spec.Timeout <= 0 {
		spec.Timeout = 10 * time.Second
	}
	if spec.Samples <= 0 {
		spec.Samples = 3
	}
	if spec.Jobs <= 0 {
		spec.Jobs = 3
	}

	url := spec.URL
	if url == "" {
		var err error
		url, err = reachableProbeURL(ctx, spec.Timeout)
		if err != nil {
			return nil, err
		}
	}

	results := make([]CheckResult, len(servers))

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan int)
	go func() {
		defer close(jobs)
		for i := range servers {
			select {
			case jobs <- i:
			case <-runCtx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < spec.Jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = probe(runCtx, servers[i], url, spec)
			}
		}()
	}
	wg.Wait()

	sort.SliceStable(results, func(a, b int) bool {
		switch {
		case results[a].OK() != results[b].OK():
			return results[a].OK()
		case results[a].Median != results[b].Median:
			return results[a].Median < results[b].Median
		}
		return results[a].Server.Index < results[b].Server.Index
	})
	return results, nil
}

func probe(ctx context.Context, s *npvs.Server, url string, spec CheckSpec) CheckResult {
	port, err := freePort()
	if err != nil {
		return CheckResult{Server: s, Err: err}
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	closer, err := Start(ctx, Options{Server: s, SocksAddr: addr, Loglevel: "none"})
	if err != nil {
		return CheckResult{Server: s, Err: err}
	}
	defer closer.Close()

	dialer, err := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: spec.Timeout})
	if err != nil {
		return CheckResult{Server: s, Err: err}
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return CheckResult{Server: s, Err: errors.New("socks dialer cannot dial with a context")}
	}

	client := &http.Client{
		Timeout: spec.Timeout,
		Transport: &http.Transport{
			DialContext:         contextDialer.DialContext,
			TLSHandshakeTimeout: spec.Timeout,
			DisableKeepAlives:   true,
		},
	}

	sample := func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("probe target answered %s", resp.Status)
		}
		return nil
	}

	if err := sample(); err != nil {
		return CheckResult{Server: s, Err: err}
	}

	timings := make([]time.Duration, 0, spec.Samples)
	for i := 0; i < spec.Samples; i++ {
		start := time.Now()
		if err := sample(); err != nil {
			if len(timings) == 0 {
				return CheckResult{Server: s, Err: err}
			}
			break
		}
		timings = append(timings, time.Since(start))
	}

	sort.Slice(timings, func(a, b int) bool { return timings[a] < timings[b] })
	return CheckResult{Server: s, Median: timings[len(timings)/2]}
}

func reachableProbeURL(ctx context.Context, timeout time.Duration) (string, error) {
	for _, url := range probeTargets {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		client := &http.Client{Timeout: timeout}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			return url, nil
		}
	}
	return "", errors.New("no probe target is reachable directly; pass -url")
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}
