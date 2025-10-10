package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/term"
	"os"
	"strings"
	"time"
)

const usage = `usage: jwtool [option...] [JWT]
  --ugly           don't pretty-print the output
  -H, --headers    include JWT headers in output
  -h, --help       print this help and exit
  --verify         verify the JWT signature
  --key            path to verification key (PEM for RS/ES/EdDSA, or raw secret file for HS*)
  assertion       generate a client assertion JWT

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
)

var modeFlag mode

// Inspect flags
var includeHeaders bool
var uglyPrint bool
var verifySig bool
var verifyKeyPath string

// Client Assertion flags
var clientAssertion *flag.FlagSet
var clientId string
var audience string
var privateKeyPath string

func init() {
	flag.Usage = func() { fmt.Print(usage) }
	flag.BoolVar(&includeHeaders, "headers", false, "Output the header content of the JWT along with claims")
	flag.BoolVar(&includeHeaders, "H", false, "Output the headers content of the JWT")
	flag.BoolVar(&uglyPrint, "ugly", false, "Don't pretty print")
	flag.BoolVar(&verifySig, "verify", false, "Verify JWT signature")
	flag.StringVar(&verifyKeyPath, "key", "", "Path to verification key (PEM for RS/ES/EdDSA, or raw secret file for HS*)")

	clientAssertion = flag.NewFlagSet("assertion", flag.ExitOnError)
	clientAssertion.Usage = func() { fmt.Print(clientAssertionUsage) }
	clientAssertion.StringVar(&clientId, "clientid", "", "Client ID")
	clientAssertion.StringVar(&clientId, "client", "", "Client ID")
	clientAssertion.StringVar(&audience, "audience", "", "Audience")
	clientAssertion.StringVar(&audience, "aud", "", "Audience")
	clientAssertion.StringVar(&privateKeyPath, "privatekey", "", "Path to RSA private key in PEM format")
	clientAssertion.StringVar(&privateKeyPath, "key", "", "Path to RSA private key in PEM format")

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
	}
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
		if verifyKeyPath == "" {
			_, _ = fmt.Fprintln(os.Stderr, "--verify requires --key to be provided")
			os.Exit(1)
		}
		alg, ok := token.Header["alg"].(string)
		if !ok || alg == "" {
			_, _ = fmt.Fprintln(os.Stderr, "Cannot determine alg from token header")
			os.Exit(1)
		}
		key, err := loadVerifyKey(alg, verifyKeyPath)
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
