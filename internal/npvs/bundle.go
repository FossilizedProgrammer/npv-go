package npvs

import (
	"fmt"
	"strings"
)

// Bundle is a decoded NPV Tunnel export.
type Bundle struct {
	Format         string
	CreatorMessage string
	Keys           [][2]string
	Links          []string
}

// splitLinks keeps the share-link lines out of a plaintext payload and drops
// the chatter an export may wrap them in.
func splitLinks(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if !strings.Contains(line, "://") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func (b *Bundle) Text() string {
	var sb strings.Builder
	if b.CreatorMessage != "" {
		sb.WriteString("// ---- creator message ----\n")
		sb.WriteString(b.CreatorMessage)
		sb.WriteString("\n\n")
	}
	sb.WriteString(strings.Join(b.Links, "\n"))
	if len(b.Keys) > 0 {
		sb.WriteString("\n\n// ---- recovered key material ----\n")
		for _, kv := range b.Keys {
			fmt.Fprintf(&sb, "// %s: %s\n", kv[0], kv[1])
		}
	}
	return sb.String()
}
