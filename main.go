package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/term"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

const usage = `usage: jwtool [option...] [JWT]
  --ugly           don't pretty-print the output
  -H, --headers    include JWT headers in output
  -h, --help       print this help and exit
  --verify         verify the JWT signature
  --key            path to verification key (PEM for RS/ES/EdDSA, or raw secret file for HS*)
  --jwks           path or URL to JWKS (used with --verify)
  assertion       generate a client assertion JWT
  version         print version information

Inspect a JWT and print its claims as JSON.

JWT can also be piped through stdin:
  echo -n "jwt" | jwtool

For best effect, pipe output to jq to get syntax highlighting:
  jwtool "jwt" | jq
`

const clientAssertionUsage = `usage: jwtool assertion [option...]
  --clientid, --client    Client ID (required)
  --audience, --aud      Audience (required)
  --privatekey, --key    Path to RSA private key in PEM format (required)
  -h, --help             print this help and exit

Generates a client assertion JWT signed with the provided RSA private key.
`

type mode int

const (
	modeInspect mode = iota
	modeAssertion
	modeVersion
)

var modeFlag mode

// Inspect flags
var includeHeaders bool
var uglyPrint bool
var verifySig bool
var verifyKeyPath string
var jwksRef string

// Client Assertion flags
var clientAssertion *flag.FlagSet
var clientId string
var audience string
var privateKeyPath string
var kid string

func init() {
	flag.Usage = func() { fmt.Print(usage) }
	flag.BoolVar(&includeHeaders, "headers", false, "Output the header content of the JWT along with claims")
	flag.BoolVar(&includeHeaders, "H", false, "Output the headers content of the JWT")
	flag.BoolVar(&uglyPrint, "ugly", false, "Don't pretty print")
	flag.BoolVar(&verifySig, "verify", false, "Verify JWT signature")
	flag.StringVar(&verifyKeyPath, "key", "", "Path to verification key (PEM for RS/ES/EdDSA, or raw secret file for HS*)")
	flag.StringVar(&jwksRef, "jwks", "", "Path or URL to JWKS (used with --verify)")

	clientAssertion = flag.NewFlagSet("assertion", flag.ExitOnError)
	clientAssertion.Usage = func() { fmt.Print(clientAssertionUsage) }
	clientAssertion.StringVar(&clientId, "clientid", "", "Client ID")
	clientAssertion.StringVar(&clientId, "client", "", "Client ID")
	clientAssertion.StringVar(&audience, "audience", "", "Audience")
	clientAssertion.StringVar(&audience, "aud", "", "Audience")
	clientAssertion.StringVar(&privateKeyPath, "privatekey", "", "Path to RSA private key in PEM format")
	clientAssertion.StringVar(&privateKeyPath, "key", "", "Path to RSA private key in PEM format")
	clientAssertion.StringVar(&kid, "kid", "", "Key ID (optional)")

	if len(os.Args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	if len(os.Args) == 1 {
		modeFlag = modeInspect
	} else if os.Args[1] == "assertion" {
		if err := clientAssertion.Parse(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error parsing flags: %s\n", err)
			os.Exit(1)
		}
		modeFlag = modeAssertion
	} else if os.Args[1] == "version" {
		modeFlag = modeVersion
	} else {
		flag.Parse()
	}
}

func main() {
	switch modeFlag {
	case modeAssertion:
		createAssertion()
	case modeInspect:
		inspect()
	case modeVersion:
		printVersion()
	}
}

// These values are intended to be set via -ldflags at build time.
// Defaults make sense for local builds.
var (
	Version string
	Commit  string
	Date    string
)

func printVersion() {

	if info, ok := debug.ReadBuildInfo(); ok {
		var rev, ts string
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.time":
				ts = s.Value
			}
		}
		if Version == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			Version = info.Main.Version
		}
		if Commit == "" && rev != "" {
			Commit = rev
		}
		if Date == "" && ts != "" {
			Date = ts
		}
	}

	if Version == "" {
		Version = "dev"
	}
	if Commit == "" {
		Commit = "unknown"
	}
	if Date == "" {
		Date = "unknown"
	}

	fmt.Printf("jwtool %s\n", Version)
	fmt.Printf("Commit: %s\n", Commit)
	fmt.Printf("Built: %s\n", Date)
}

func createAssertion() {
	if clientId == "" || audience == "" || privateKeyPath == "" {
		clientAssertion.Usage()
		os.Exit(1)
	}

	key, err := os.ReadFile(privateKeyPath)
	if err != nil {
		fmt.Printf("Error reading private key: %s\n", err)
		os.Exit(1)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		fmt.Printf("Error parsing private key: %s\n", err)
		os.Exit(1)
	}
	now := time.Now().UTC()
	expires := now.Add(time.Minute)
	jti, err := newJti()
	if err != nil {
		fmt.Printf("Error generating jti: %s\n", err)
		os.Exit(1)
	}
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.MapClaims{
			"iss": clientId,
			"sub": clientId,
			"nbf": now.Unix(),
			"iat": now.Unix(),
			"exp": expires.Unix(),
			"jti": jti,
			"aud": audience,
		})
	token.Header["typ"] = "client-authentication+jwt"
	if kid != "" {
		token.Header["kid"] = kid
	}
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		fmt.Printf("Error signing token: %s\n", err)
		os.Exit(1)
	}
	fmt.Println(tokenString)
}

func inspect() {
	var jwtString string
	if flag.NArg() > 0 {
		jwtString = flag.Arg(0)
	} else {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			flag.Usage()
			os.Exit(1)
		}
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			jwtString = scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error reading from stdin: %s\n", err)
			os.Exit(1)
		}
	}

	jwtString = strings.TrimSpace(jwtString)

	var token *jwt.Token
	var err error
	token, err = jwt.Parse(jwtString, nil)
	if err != nil {
		if !errors.Is(err, jwt.ErrTokenUnverifiable) {
			_, _ = fmt.Fprintf(os.Stderr, "Error parsing JWT: %s\n", err)
			os.Exit(1)
		}
	}

	if verifySig {
		if verifyKeyPath == "" && jwksRef == "" {
			_, _ = fmt.Fprintln(os.Stderr, "--verify requires --key or --jwks to be provided")
			os.Exit(1)
		}
		if verifyKeyPath != "" && jwksRef != "" {
			_, _ = fmt.Fprintln(os.Stderr, "--key and --jwks are mutually exclusive")
			os.Exit(1)
		}
		alg, ok := token.Header["alg"].(string)
		if !ok || alg == "" {
			_, _ = fmt.Fprintln(os.Stderr, "Cannot determine alg from token header")
			os.Exit(1)
		}
		var key interface{}
		var err error
		if jwksRef != "" {
			k, kerr := loadKeyFromJWKS(jwksRef, token)
			if kerr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Error loading key from JWKS: %s\n", kerr)
				os.Exit(1)
			}
			key = k
		} else {
			key, err = loadVerifyKey(alg, verifyKeyPath)
		}
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error loading verification key: %s\n", err)
			os.Exit(1)
		}
		token, err = jwt.Parse(jwtString, func(t *jwt.Token) (interface{}, error) { return key, nil }, jwt.WithValidMethods([]string{alg}), jwt.WithoutClaimsValidation())
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Signature verification failed: %s\n", err)
			os.Exit(1)
		}
		if !token.Valid {
			_, _ = fmt.Fprintln(os.Stderr, "Signature verification failed: token invalid")
			os.Exit(1)
		}
	}

	if includeHeaders {
		fmt.Println(format(token.Header))
	}
	fmt.Println(format(token.Claims))
}

func format(v interface{}) string {
	var out []byte
	var err error
	if uglyPrint {
		out, err = json.Marshal(v)
	} else {
		out, err = json.MarshalIndent(v, "", "  ")
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "marshalling error: %s\n", err)
		os.Exit(1)
	}
	return string(out)
}

func newJti() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func loadVerifyKey(alg string, keyPath string) (interface{}, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	a := strings.ToUpper(alg)
	switch a {
	case "HS256", "HS384", "HS512":
		return data, nil // raw secret bytes
	case "RS256", "RS384", "RS512":
		if pub, err := jwt.ParseRSAPublicKeyFromPEM(data); err == nil {
			return pub, nil
		}
		if priv, err := jwt.ParseRSAPrivateKeyFromPEM(data); err == nil {
			return &priv.PublicKey, nil
		}
		return nil, fmt.Errorf("unable to parse RSA key from PEM")
	case "ES256", "ES384", "ES512":
		if pub, err := jwt.ParseECPublicKeyFromPEM(data); err == nil {
			return pub, nil
		}
		if priv, err := jwt.ParseECPrivateKeyFromPEM(data); err == nil {
			return &priv.PublicKey, nil
		}
		return nil, fmt.Errorf("unable to parse EC key from PEM")
	case "EDDSA":
		if pub, err := jwt.ParseEdPublicKeyFromPEM(data); err == nil {
			return pub, nil
		}
		if priv, err := jwt.ParseEdPrivateKeyFromPEM(data); err == nil {
			key, ok := priv.(ed25519.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("not an Ed25519 private key")
			}
			return key.Public(), nil
		}
		return nil, fmt.Errorf("unable to parse Ed25519 key from PEM")
	default:
		return nil, fmt.Errorf("unsupported alg: %s", alg)
	}
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	// OCT (HMAC)
	K string `json:"k,omitempty"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func loadKeyFromJWKS(ref string, token *jwt.Token) (interface{}, error) {
	data, err := readRef(ref)
	if err != nil {
		return nil, err
	}
	var set jwks
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	var kid string
	if v, ok := token.Header["kid"].(string); ok {
		kid = v
	}

	var selected *jwk
	if kid != "" {
		for i := range set.Keys {
			if set.Keys[i].Kid == kid {
				selected = &set.Keys[i]
				break
			}
		}
		if selected == nil {
			return nil, fmt.Errorf("no JWK with kid %q found", kid)
		}
	} else {
		if len(set.Keys) == 1 {
			selected = &set.Keys[0]
		} else {
			return nil, fmt.Errorf("multiple keys in JWKS and token has no kid")
		}
	}

	return jwkToKey(*selected)
}

func jwkToKey(j jwk) (interface{}, error) {
	switch strings.ToUpper(j.Kty) {
	case "RSA":
		if j.N == "" || j.E == "" {
			return nil, fmt.Errorf("invalid RSA JWK: missing n or e")
		}
		nBytes, err := b64urlDecode(j.N)
		if err != nil {
			return nil, fmt.Errorf("decode n: %w", err)
		}
		eBytes, err := b64urlDecode(j.E)
		if err != nil {
			return nil, fmt.Errorf("decode e: %w", err)
		}
		n := new(big.Int).SetBytes(nBytes)
		var eInt int
		for _, b := range eBytes {
			eInt = eInt<<8 | int(b)
		}
		return &rsa.PublicKey{N: n, E: eInt}, nil
	case "EC":
		if j.Crv == "" || j.X == "" || j.Y == "" {
			return nil, fmt.Errorf("invalid EC JWK: missing crv/x/y")
		}
		var curve elliptic.Curve
		switch strings.ToUpper(j.Crv) {
		case "P-256", "SECP256R1":
			curve = elliptic.P256()
		case "P-384", "SECP384R1":
			curve = elliptic.P384()
		case "P-521", "SECP521R1":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", j.Crv)
		}
		xb, err := b64urlDecode(j.X)
		if err != nil {
			return nil, fmt.Errorf("decode x: %w", err)
		}
		yb, err := b64urlDecode(j.Y)
		if err != nil {
			return nil, fmt.Errorf("decode y: %w", err)
		}
		x := new(big.Int).SetBytes(xb)
		y := new(big.Int).SetBytes(yb)
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		if strings.EqualFold(j.Crv, "Ed25519") {
			xb, err := b64urlDecode(j.X)
			if err != nil {
				return nil, fmt.Errorf("decode x: %w", err)
			}
			if l := len(xb); l != ed25519.PublicKeySize {
				return nil, fmt.Errorf("invalid Ed25519 key length: %d", l)
			}
			return ed25519.PublicKey(xb), nil
		}
		return nil, fmt.Errorf("unsupported OKP curve: %s", j.Crv)
	case "OCT":
		if j.K == "" {
			return nil, fmt.Errorf("invalid oct JWK: missing k")
		}
		kb, err := b64urlDecode(j.K)
		if err != nil {
			return nil, fmt.Errorf("decode k: %w", err)
		}
		return kb, nil
	default:
		return nil, fmt.Errorf("unsupported kty: %s", j.Kty)
	}
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func readRef(ref string) ([]byte, error) {
	u, err := url.Parse(ref)
	if err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(ref)
		if err != nil {
			return nil, fmt.Errorf("fetch JWKS: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("fetch JWKS: HTTP %d", resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read JWKS: %w", err)
		}
		return b, nil
	}
	// Fallback to file path
	b, err := os.ReadFile(ref)
	if err != nil {
		return nil, fmt.Errorf("read JWKS file: %w", err)
	}
	return b, nil
}
