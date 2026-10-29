package npvs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

const (
	npvsWrapSize  = 60
	npvsSaltSize  = 16
	npvsKdfAppKey = "wbaes-ctr-sha256"
	npvsKdfPass   = "pbkdf2-hmac-sha256"
	npvsKeyGen    = 1
	npvsMinIters  = 1
	npvsMaxIters  = 10000000
)

type npvsPassphraseWrap struct {
	Iters int    `json:"iters"`
	Kdf   string `json:"kdf"`
	Salt  string `json:"salt"`
	Wrap  string `json:"wrap"`
}

type npvsAppKeyWrap struct {
	Kdf   string `json:"kdf"`
	KeyID int    `json:"keyId"`
	Salt  string `json:"salt"`
	Wrap  string `json:"wrap"`
}

type npvsConfigPolicy struct {
	AttestationLevel    string  `json:"attestationLevel"`
	ConfigVersion       int     `json:"configVersion"`
	CustomServerMessage string  `json:"customServerMessage"`
	DisplayMessage      string  `json:"displayMessage"`
	ExpiresAt           *string `json:"expiresAt"`
	OnlyMobileNetwork   bool    `json:"onlyMobileNetwork"`
}

type npvsHeader struct {
	V        int    `json:"v"`
	ConfigID string `json:"configId"`
	IssuedAt string `json:"issuedAt"`
	Creator  struct {
		Fp string `json:"fp"`
		Pk string `json:"pk"`
	} `json:"creator"`
	AppKey     *npvsAppKeyWrap     `json:"appKey"`
	Passphrase *npvsPassphraseWrap `json:"passphrase"`
	Policy     npvsConfigPolicy    `json:"policy"`
	Recipients []json.RawMessage   `json:"recipients"`
}

type npvsEnvelope struct {
	headerRaw []byte
	hdr       npvsHeader
	nonce     []byte
	body      []byte
	sig       []byte
}

func parseNpvVEnvelope(b []byte) (*npvsEnvelope, error) {
	if len(b) < 89 {
		return nil, fmt.Errorf("too short: %d bytes", len(b))
	}
	if b[0] != 'N' || b[1] != 'P' || b[2] != 'V' || b[3] != 'S' {
		return nil, fmt.Errorf("bad magic")
	}
	if b[5] > 1 {
		return nil, fmt.Errorf("unsupported version %d", b[4])
	}

	hdrLen := int(binary.BigEndian.Uint32(b[5:9]))
	if hdrLen < 0 || 9+hdrLen > len(b) {
		return nil, fmt.Errorf("invalid header length: %d", hdrLen)
	}

	e := &npvsEnvelope{headerRaw: b[9 : 9+hdrLen]}
	if err := json.Unmarshal(e.headerRaw, &e.hdr); err != nil {
		return nil, fmt.Errorf("header parse: %w", err)
	}

	off := 9 + hdrLen
	if off+12+4 > len(b) {
		return nil, fmt.Errorf("truncated body nonce/length")
	}
	e.nonce = b[off : off+12]
	bodyLen := int(binary.BigEndian.Uint32(b[off+12 : off+16]))
	off += 16

	if bodyLen < 16 || off+bodyLen+64 > len(b) {
		return nil, fmt.Errorf("invalid body length: %d", bodyLen)
	}
	e.body = b[off : off+bodyLen]
	e.sig = b[off+bodyLen : off+bodyLen+64]

	return e, nil
}

// Decode opens an NPV Tunnel config export in any of its three container
// shapes and returns the share links it carries.
func Decode(data []byte, passphrase string) (*Bundle, error) {
	if isNpvOpenEnvelope(data) {
		return decodeOpen(data)
	}
	if marker := npvLegacyMarkerOf(data); marker != "" {
		return nil, fmt.Errorf("npvs: %s container is a legacy sealed export that is not supported", marker)
	}
	if isNpvGen2Envelope(data) {
		return decodeGen2(data, passphrase)
	}
	return decodeV1(data, passphrase)
}

// NeedsPassphrase reports whether opening this export requires a passphrase
// the sharer must supply.
func NeedsPassphrase(data []byte) bool {
	if env, err := parseNpvGen2Envelope(data); err == nil {
		return env.needsPassphrase()
	}
	env, err := parseNpvVEnvelope(data)
	return err == nil && env.needsPassphrase()
}

func decodeV1(data []byte, password string) (*Bundle, error) {
	env, err := parseNpvVEnvelope(data)
	if err != nil {
		return nil, err
	}

	pt, keys, err := decryptEnvelope(env, password)
	if err != nil {
		return nil, env.passphraseHint(err)
	}

	text := decodeNpvSentinels(string(pt))
	if isNpvOpenEnvelope([]byte(text)) {
		inner, err := decodeOpen([]byte(text))
		if err == nil {
			inner.CreatorMessage = env.creatorMessage()
			inner.Keys = append(keys, inner.Keys...)
			return inner, nil
		}
	}

	b := &Bundle{
		Format:         "npvs-v1",
		CreatorMessage: env.creatorMessage(),
		Keys:           keys,
		Links:          splitLinks(text),
	}
	return b, nil
}

func (e *npvsEnvelope) needsPassphrase() bool {
	return e.hdr.Passphrase != nil && e.hdr.AppKey == nil
}

func (e *npvsEnvelope) creatorMessage() string {
	var parts []string
	for _, m := range []string{e.hdr.Policy.DisplayMessage, e.hdr.Policy.CustomServerMessage} {
		if m = strings.TrimSpace(strings.ReplaceAll(m, "\r\n", "\n")); m != "" {
			parts = append(parts, m)
		}
	}
	return strings.Join(parts, "\n")
}

func (e *npvsEnvelope) passphraseHint(err error) error {
	if !e.needsPassphrase() {
		return err
	}
	return fmt.Errorf("%w\n[!] this config is passphrase-protected; whoever shared it must provide the passphrase (creator message: %q)",
		err, e.creatorMessage())
}

func decryptEnvelope(env *npvsEnvelope, password string) (pt []byte, keys [][2]string, err error) {
	keys = append(keys,
		[2]string{"configId", env.hdr.ConfigID},
		[2]string{"creator.fp", env.hdr.Creator.Fp},
		[2]string{"creator.pk", env.hdr.Creator.Pk},
	)

	var dek []byte
	switch {
	case env.hdr.AppKey != nil:
		dek, err = unwrapAppKey(env.hdr.AppKey)
	case env.hdr.Passphrase != nil:
		dek, err = unwrapPassphrase(env.hdr.Passphrase, password)
	case len(env.hdr.Recipients) > 0:
		err = fmt.Errorf("envelope uses recipient ECDH wraps; recipient private key required")
	default:
		err = fmt.Errorf("no supported unwrap target (no appKey, no passphrase)")
	}
	if err != nil {
		return nil, keys, err
	}
	keys = append(keys, [2]string{"DEK/CEK (hex)", hex.EncodeToString(dek)})

	body, err := chachaOpen(dek, env.nonce, env.body, env.headerRaw)
	if err != nil {
		return nil, keys, fmt.Errorf("payload decrypt failed: %w", err)
	}

	return body, keys, nil
}

func unwrapAppKey(a *npvsAppKeyWrap) ([]byte, error) {
	if a.Kdf != npvsKdfAppKey {
		return nil, fmt.Errorf("unsupported appkey kdf %q", a.Kdf)
	}
	if a.KeyID != npvsKeyGen {
		return nil, fmt.Errorf("no custodian for generation %d", a.KeyID)
	}

	salt, err := b64UrlNoPad(a.Salt)
	if err != nil {
		return nil, err
	}
	if len(salt) != npvsSaltSize {
		return nil, fmt.Errorf("salt must be %d bytes", npvsSaltSize)
	}

	wrap, err := b64UrlNoPad(a.Wrap)
	if err != nil {
		return nil, err
	}
	if len(wrap) != npvsWrapSize {
		return nil, fmt.Errorf("wrap must be %d bytes", npvsWrapSize)
	}

	kdks := custodianKDKs(salt)
	if len(kdks) == 0 {
		return nil, fmt.Errorf("whitebox KDK derivation failed")
	}
	for _, kdk := range kdks {
		if dek, err := chachaOpen(kdk, wrap[:12], wrap[12:], salt); err == nil {
			return dek, nil
		}
	}
	return nil, fmt.Errorf("no custodian key matched (tried %d)", len(kdks))
}

func unwrapPassphrase(p *npvsPassphraseWrap, password string) ([]byte, error) {
	if p.Kdf != npvsKdfPass {
		return nil, fmt.Errorf("unsupported passphrase kdf %q", p.Kdf)
	}
	if p.Iters < npvsMinIters || p.Iters > npvsMaxIters {
		return nil, fmt.Errorf("bad iteration count %d", p.Iters)
	}
	if password == "" {
		return nil, fmt.Errorf("passphrase required to open this config")
	}

	salt, err := b64UrlNoPad(p.Salt)
	if err != nil {
		return nil, err
	}

	wrap, err := b64UrlNoPad(p.Wrap)
	if err != nil {
		return nil, err
	}
	if len(wrap) != npvsWrapSize {
		return nil, fmt.Errorf("wrap must be %d bytes", npvsWrapSize)
	}

	derived := customPBKDF2HmacSha256([]byte(password), salt, p.Iters, 32)
	dek, err := chachaOpen(derived, wrap[:12], wrap[12:], salt)
	if err != nil {
		return nil, fmt.Errorf("incorrect passphrase")
	}
	return dek, nil
}

func customPBKDF2HmacSha256(passphraseBytes, salt []byte, iterations, dkLen int) []byte {
	blocks := (dkLen + 31) / 32
	out := make([]byte, dkLen)
	counter := make([]byte, 4)

	for i, written := 1, 0; i <= blocks; i++ {
		binary.BigEndian.PutUint32(counter, uint32(i))

		mac := hmac.New(sha256.New, passphraseBytes)
		mac.Write(salt)
		mac.Write(counter)
		digest := mac.Sum(nil)

		blockXor := slices.Clone(digest)

		for j := 2; j <= iterations; j++ {
			mac.Reset()
			mac.Write(digest)
			digest = mac.Sum(nil)
			for idx := range blockXor {
				blockXor[idx] ^= digest[idx]
			}
		}

		n := min(32, dkLen-written)
		copy(out[written:written+n], blockXor[:n])
		written += n
	}

	return out
}
