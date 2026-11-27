package link

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"

	nbcrypto "github.com/Nulliance/nullbin-cli/crypto"
)

const (
	idLength             = 32
	tokenBase64URLLength = 43
	secretBase64URLLen   = 22
)

var (
	ErrInvalidID       = errors.New("link: invalid paste ID")
	ErrInvalidToken    = errors.New("link: invalid capability token")
	ErrInvalidURL      = errors.New("link: invalid Nullbin URL")
	ErrInvalidFragment = errors.New("link: missing or invalid URL fragment")
)

// ValidID reports whether id is exactly 32 lowercase hexadecimal characters.
func ValidID(id string) bool {
	if len(id) != idLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isBase64URLChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ValidToken reports whether tok is a canonical 43-character unpadded
// base64url encoding of 32 bytes.
func ValidToken(tok string) bool {
	b, err := DecodeCanonicalBase64URL(tok, nbcrypto.KeyBytes)
	if err != nil {
		return false
	}
	clear(b)
	return true
}

// DecodeCanonicalBase64URL decodes unpadded base64url of exactly wantBytes
// bytes and rejects any non-canonical encoding (such as stray trailing bits).
func DecodeCanonicalBase64URL(s string, wantBytes int) ([]byte, error) {
	if !isBase64URLChars(s) {
		return nil, ErrInvalidFragment
	}
	if len(s) != base64.RawURLEncoding.EncodedLen(wantBytes) {
		return nil, ErrInvalidFragment
	}
	out, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(out) != wantBytes {
		clear(out)
		return nil, ErrInvalidFragment
	}
	if base64.RawURLEncoding.EncodeToString(out) != s {
		clear(out)
		return nil, ErrInvalidFragment
	}
	return out, nil
}

// ViewLink is a parsed Nullbin paste view URL (/p/<id>#<key>[.b][.r<secret>]).
type ViewLink struct {
	Origin          string
	ID              string
	Key             []byte
	Burn            bool
	RecipientSecret []byte // nil for shared link, 16 bytes for separate recipient link
}

// Close zeros sensitive key material held in the parsed view link.
func (v *ViewLink) Close() {
	if v == nil {
		return
	}
	clear(v.Key)
	clear(v.RecipientSecret)
	v.Key = nil
	v.RecipientSecret = nil
}

// DeleteLink is a parsed Nullbin delete URL (/d/<id>#d.<token>[.r]).
type DeleteLink struct {
	Origin        string
	ID            string
	DeleteToken   string
	HasRecipients bool
}

// FormatViewURL formats a Nullbin view URL.
func FormatViewURL(origin, id string, key []byte, burn bool, recipientSecret []byte) (string, error) {
	canonical, err := ValidateOrigin(origin)
	if err != nil {
		return "", err
	}
	if !ValidID(id) {
		return "", ErrInvalidID
	}
	if len(key) != nbcrypto.KeyBytes {
		return "", nbcrypto.ErrInvalidKey
	}
	if recipientSecret != nil && len(recipientSecret) != nbcrypto.RecipientSecretBytes {
		return "", nbcrypto.ErrInvalidRecipientSecret
	}

	var b strings.Builder
	b.WriteString(canonical)
	b.WriteString("/p/")
	b.WriteString(id)
	b.WriteByte('#')
	b.WriteString(base64.RawURLEncoding.EncodeToString(key))
	if burn {
		b.WriteString(".b")
	}
	if recipientSecret != nil {
		b.WriteString(".r")
		b.WriteString(base64.RawURLEncoding.EncodeToString(recipientSecret))
	}
	return b.String(), nil
}

// FormatDeleteURL formats a Nullbin delete URL.
func FormatDeleteURL(origin, id, deleteToken string, hasRecipients bool) (string, error) {
	canonical, err := ValidateOrigin(origin)
	if err != nil {
		return "", err
	}
	if !ValidID(id) {
		return "", ErrInvalidID
	}
	if !ValidToken(deleteToken) {
		return "", ErrInvalidToken
	}

	var b strings.Builder
	b.WriteString(canonical)
	b.WriteString("/d/")
	b.WriteString(id)
	b.WriteString("#d.")
	b.WriteString(deleteToken)
	if hasRecipients {
		b.WriteString(".r")
	}
	return b.String(), nil
}

// ParseKeyFragment parses "#<key>", "#<key>.b", "#<key>.r<secret>", or
// "#<key>.b.r<secret>" (with or without leading '#').
func ParseKeyFragment(fragment string) (key []byte, burn bool, recipient []byte, err error) {
	f := strings.TrimPrefix(fragment, "#")
	if f == "" {
		return nil, false, nil, ErrInvalidFragment
	}
	parts := strings.Split(f, ".")
	k := parts[0]
	rest := parts[1:]

	if len(rest) > 0 && rest[0] == "b" {
		burn = true
		rest = rest[1:]
	}
	var secretStr string
	hasSecret := false
	if len(rest) > 0 && strings.HasPrefix(rest[0], "r") {
		secretStr = rest[0][1:]
		hasSecret = true
		rest = rest[1:]
	}
	if len(rest) > 0 || len(k) != tokenBase64URLLength || (hasSecret && len(secretStr) != secretBase64URLLen) {
		return nil, false, nil, ErrInvalidFragment
	}

	key, err = DecodeCanonicalBase64URL(k, nbcrypto.KeyBytes)
	if err != nil {
		return nil, false, nil, ErrInvalidFragment
	}
	if hasSecret {
		recipient, err = DecodeCanonicalBase64URL(secretStr, nbcrypto.RecipientSecretBytes)
		if err != nil {
			clear(key)
			return nil, false, nil, ErrInvalidFragment
		}
	}
	return key, burn, recipient, nil
}

// ParseDeleteFragment parses "#d.<deleteToken>" or "#d.<deleteToken>.r".
func ParseDeleteFragment(fragment string) (token string, hasRecipients bool, err error) {
	f := strings.TrimPrefix(fragment, "#")
	if !strings.HasPrefix(f, "d.") {
		return "", false, ErrInvalidFragment
	}
	body := f[2:]
	if strings.HasSuffix(body, ".r") {
		hasRecipients = true
		body = body[:len(body)-2]
	}
	if len(body) != tokenBase64URLLength || !isBase64URLChars(body) {
		return "", false, ErrInvalidFragment
	}
	// Note: delete tokens generated by the server are 43 base64url characters (256 bits).
	if !ValidToken(body) {
		return "", false, ErrInvalidFragment
	}
	return body, hasRecipients, nil
}

// ParseViewURL parses and strictly validates a Nullbin paste view URL.
// If no scheme is present (e.g. "paste.example.com/p/<id>#<key>"), "https://"
// is assumed automatically; explicit "http://" is rejected for non-loopback hosts.
func ParseViewURL(rawURL string) (*ViewLink, error) {
	rawURL = strings.TrimSpace(rawURL)
	normalized, err := normalizeImplicitHTTPS(rawURL)
	if err != nil {
		return nil, ErrInvalidURL
	}
	u, err := url.Parse(normalized)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" {
		return nil, ErrInvalidURL
	}
	originRaw := u.Scheme + "://" + u.Host
	origin, err := ValidateOrigin(originRaw)
	if err != nil {
		return nil, err
	}

	id, ok := strings.CutPrefix(u.Path, "/p/")
	if !ok || !ValidID(id) {
		return nil, ErrInvalidURL
	}

	key, burn, recipient, err := ParseKeyFragment(u.Fragment)
	if err != nil {
		return nil, err
	}
	return &ViewLink{
		Origin:          origin,
		ID:              id,
		Key:             key,
		Burn:            burn,
		RecipientSecret: recipient,
	}, nil
}

// ParseDeleteURL parses and strictly validates a Nullbin delete URL.
// If no scheme is present (e.g. "paste.example.com/d/<id>#d.<token>"),
// "https://" is assumed automatically; explicit "http://" is rejected for non-loopback hosts.
func ParseDeleteURL(rawURL string) (*DeleteLink, error) {
	rawURL = strings.TrimSpace(rawURL)
	normalized, err := normalizeImplicitHTTPS(rawURL)
	if err != nil {
		return nil, ErrInvalidURL
	}
	u, err := url.Parse(normalized)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" {
		return nil, ErrInvalidURL
	}
	originRaw := u.Scheme + "://" + u.Host
	origin, err := ValidateOrigin(originRaw)
	if err != nil {
		return nil, err
	}

	id, ok := strings.CutPrefix(u.Path, "/d/")
	if !ok || !ValidID(id) {
		return nil, ErrInvalidURL
	}

	token, hasRecipients, err := ParseDeleteFragment(u.Fragment)
	if err != nil {
		return nil, err
	}
	return &DeleteLink{
		Origin:        origin,
		ID:            id,
		DeleteToken:   token,
		HasRecipients: hasRecipients,
	}, nil
}
