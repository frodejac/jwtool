package generate

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/frodejac/jwtool/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

// StringSlice implements flag.Value for repeatable string flags.
type StringSlice []string

func (s *StringSlice) String() string { return strings.Join(*s, ",") }
func (s *StringSlice) Set(val string) error {
	*s = append(*s, val)
	return nil
}

// ClaimEntry represents a single key=value claim pair.
type ClaimEntry struct {
	Key   string
	Value string
}

// ClaimList implements flag.Value for repeatable --claim key=value flags.
type ClaimList []ClaimEntry

func (c *ClaimList) String() string { return "" }
func (c *ClaimList) Set(val string) error {
	idx := strings.IndexByte(val, '=')
	if idx < 1 {
		return fmt.Errorf("invalid claim %q: expected key=value", val)
	}
	*c = append(*c, ClaimEntry{Key: val[:idx], Value: val[idx+1:]})
	return nil
}

// Config holds the configuration for the generate command.
type Config struct {
	Alg    string
	Key    string
	Kid    string
	Typ    string
	Iss    string
	Sub    string
	Aud    StringSlice
	Exp    string
	Nbf    string
	Iat    string
	Jti    string
	Scope  string
	Nonce  string
	Azp    string
	Acr    string
	Claims ClaimList
}

// Run executes the generate command.
func Run(cfg Config, stdout, stderr io.Writer) error {
	if cfg.Alg == "" || cfg.Key == "" {
		return fmt.Errorf("--alg and --key are required")
	}

	method, err := crypto.SigningMethodFromAlg(cfg.Alg)
	if err != nil {
		return fmt.Errorf("Error: %s", err)
	}

	key, err := crypto.LoadSigningKey(cfg.Alg, cfg.Key)
	if err != nil {
		return fmt.Errorf("Error loading signing key: %s", err)
	}

	now := time.Now().UTC()
	claims := jwt.MapClaims{}

	// Default iat to now
	claims["iat"] = now.Unix()

	// Default jti to auto-generated
	jtiVal, err := crypto.NewJti()
	if err != nil {
		return fmt.Errorf("Error generating jti: %s", err)
	}
	claims["jti"] = jtiVal

	if cfg.Iss != "" {
		claims["iss"] = cfg.Iss
	}
	if cfg.Sub != "" {
		claims["sub"] = cfg.Sub
	}
	if len(cfg.Aud) == 1 {
		claims["aud"] = cfg.Aud[0]
	} else if len(cfg.Aud) > 1 {
		claims["aud"] = []string(cfg.Aud)
	}
	if cfg.Exp != "" {
		v, err := ParseTimeFlag(cfg.Exp, now)
		if err != nil {
			return fmt.Errorf("Error parsing --exp: %s", err)
		}
		claims["exp"] = v
	}
	if cfg.Nbf != "" {
		v, err := ParseTimeFlag(cfg.Nbf, now)
		if err != nil {
			return fmt.Errorf("Error parsing --nbf: %s", err)
		}
		claims["nbf"] = v
	}
	if cfg.Iat != "" {
		ts, err := strconv.ParseInt(cfg.Iat, 10, 64)
		if err != nil {
			return fmt.Errorf("Error parsing --iat: expected Unix timestamp")
		}
		claims["iat"] = ts
	}
	if cfg.Jti != "" {
		claims["jti"] = cfg.Jti
	}
	if cfg.Scope != "" {
		claims["scope"] = cfg.Scope
	}
	if cfg.Nonce != "" {
		claims["nonce"] = cfg.Nonce
	}
	if cfg.Azp != "" {
		claims["azp"] = cfg.Azp
	}
	if cfg.Acr != "" {
		claims["acr"] = cfg.Acr
	}

	// Apply arbitrary claims last (intentionally overrides named flags)
	for _, c := range cfg.Claims {
		claims[c.Key] = ParseClaimValue(c.Value)
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header["typ"] = cfg.Typ
	if cfg.Kid != "" {
		token.Header["kid"] = cfg.Kid
	}

	tokenString, err := token.SignedString(key)
	if err != nil {
		return fmt.Errorf("Error signing token: %s", err)
	}
	fmt.Fprintln(stdout, tokenString)
	return nil
}

// ParseTimeFlag parses a time value as either a Go duration relative to now
// or a Unix timestamp.
func ParseTimeFlag(val string, now time.Time) (int64, error) {
	if d, err := time.ParseDuration(val); err == nil {
		return now.Add(d).Unix(), nil
	}
	ts, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid time value %q: expected Go duration (e.g. 1h) or Unix timestamp", val)
	}
	return ts, nil
}

// ParseClaimValue auto-detects the type of a claim value string.
func ParseClaimValue(raw string) interface{} {
	if raw == "true" {
		return true
	}
	if raw == "false" {
		return false
	}
	if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil {
		return f
	}
	if (strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}")) ||
		(strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]")) {
		var v interface{}
		if err := json.Unmarshal([]byte(raw), &v); err == nil {
			return v
		}
	}
	return raw
}
