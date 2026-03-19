package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/frodejac/jwtool/internal/assertion"
	"github.com/frodejac/jwtool/internal/generate"
	"github.com/frodejac/jwtool/internal/inspect"
	"github.com/frodejac/jwtool/internal/jwks"
	"golang.org/x/term"
)

const usage = `usage: jwtool [option...] [JWT]
  --ugly           don't pretty-print the output
  -H, --headers    include JWT headers in output
  -h, --help       print this help and exit
  --verify         verify the JWT signature
  --key            path to verification key (PEM for RS/ES/EdDSA, or raw secret file for HS*)
  --jwks           path or URL to JWKS (used with --verify)
  generate        generate a signed JWT with arbitrary claims
  jwks           convert keys to JWKS
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

const jwksUsage = `usage: jwtool jwks [option...]
  -in <path>           Input key file (PEM for RS/ES/EdDSA, certificate, or raw secret for HS*)
  -out <path>          Output JWKS file (defaults to stdout)
  --alg <alg>          Optional alg claim to set on each JWK
  --use <use>          Optional use (e.g., 'sig' or 'enc') to set on each JWK
  --kid <kid>          Optional key ID to set (only valid for a single key)
  --private            Include private key material when applicable (not recommended)
  --ext                Set "ext" (extractable) to true on each JWK'
  --ugly               Don't pretty-print output

Convert keys to a JWKS (JSON Web Key Set). When given a private key, the
public components are exported by default. For symmetric keys (HS*), use
--private to include the secret material (k) in the output.
`

const generateUsage = `usage: jwtool generate [option...]
  --alg <alg>       Signing algorithm (required): HS256/384/512, RS256/384/512, ES256/384/512, EdDSA
  --key <path>      Path to signing key (required): PEM private key or raw HMAC secret file
  --kid <kid>       Key ID header
  --typ <typ>       Token type header (default: "JWT")
  --iss <iss>       Issuer
  --sub <sub>       Subject
  --aud <aud>       Audience (repeatable; single value → string, multiple → array)
  --exp <exp>       Expiration: Go duration relative to now (e.g. 1h) or Unix timestamp
  --nbf <nbf>       Not before: Go duration relative to now or Unix timestamp
  --iat <iat>       Issued at: Unix timestamp (default: now)
  --jti <jti>       JWT ID (default: auto-generated)
  --scope <scope>   Scope claim
  --nonce <nonce>   Nonce claim
  --azp <azp>       Authorized party
  --acr <acr>       Auth context class reference
  --claim key=value Arbitrary claim (repeatable, auto-detects value type)
  -h, --help        print this help and exit

Generate a signed JWT with the specified claims and signing key.
`

type mode int

const (
	modeInspect mode = iota
	modeAssertion
	modeJWKS
	modeVersion
	modeGenerate
)

// Inspect flags
var (
	modeFlag      mode
	includeHeaders bool
	uglyPrint      bool
	verifySig      bool
	verifyKeyPath  string
	jwksRef        string
)

// Client Assertion flags
var (
	clientAssertionFlags *flag.FlagSet
	clientId             string
	audience             string
	privateKeyPath       string
	kid                  string
)

// Generate flags
var (
	generateFlags *flag.FlagSet
	genAlg        string
	genKey        string
	genKid        string
	genTyp        string
	genIss        string
	genSub        string
	genAud        generate.StringSlice
	genExp        string
	genNbf        string
	genIat        string
	genJti        string
	genScope      string
	genNonce      string
	genAzp        string
	genAcr        string
	genClaims     generate.ClaimList
)

// JWKS flags
var (
	jwksFlags          *flag.FlagSet
	jwksIn             string
	jwksOut            string
	jwksAlg            string
	jwksUse            string
	jwksKid            string
	jwksIncludePrivate bool
	jwksUgly           bool
	jwksExt            bool
)

func init() {
	flag.Usage = func() { fmt.Print(usage) }
	flag.BoolVar(&includeHeaders, "headers", false, "Output the header content of the JWT along with claims")
	flag.BoolVar(&includeHeaders, "H", false, "Output the headers content of the JWT")
	flag.BoolVar(&uglyPrint, "ugly", false, "Don't pretty print")
	flag.BoolVar(&verifySig, "verify", false, "Verify JWT signature")
	flag.StringVar(&verifyKeyPath, "key", "", "Path to verification key (PEM for RS/ES/EdDSA, or raw secret file for HS*)")
	flag.StringVar(&jwksRef, "jwks", "", "Path or URL to JWKS (used with --verify)")

	clientAssertionFlags = flag.NewFlagSet("assertion", flag.ExitOnError)
	clientAssertionFlags.Usage = func() { fmt.Print(clientAssertionUsage) }
	clientAssertionFlags.StringVar(&clientId, "clientid", "", "Client ID")
	clientAssertionFlags.StringVar(&clientId, "client", "", "Client ID")
	clientAssertionFlags.StringVar(&audience, "audience", "", "Audience")
	clientAssertionFlags.StringVar(&audience, "aud", "", "Audience")
	clientAssertionFlags.StringVar(&privateKeyPath, "privatekey", "", "Path to RSA private key in PEM format")
	clientAssertionFlags.StringVar(&privateKeyPath, "key", "", "Path to RSA private key in PEM format")
	clientAssertionFlags.StringVar(&kid, "kid", "", "Key ID (optional)")

	if len(os.Args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	if len(os.Args) == 1 {
		modeFlag = modeInspect
	} else if os.Args[1] == "assertion" {
		if err := clientAssertionFlags.Parse(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error parsing flags: %s\n", err)
			os.Exit(1)
		}
		modeFlag = modeAssertion
	} else if os.Args[1] == "generate" {
		generateFlags = flag.NewFlagSet("generate", flag.ExitOnError)
		generateFlags.Usage = func() { fmt.Print(generateUsage) }
		generateFlags.StringVar(&genAlg, "alg", "", "Signing algorithm")
		generateFlags.StringVar(&genKey, "key", "", "Path to signing key")
		generateFlags.StringVar(&genKid, "kid", "", "Key ID header")
		generateFlags.StringVar(&genTyp, "typ", "JWT", "Token type header")
		generateFlags.StringVar(&genIss, "iss", "", "Issuer")
		generateFlags.StringVar(&genSub, "sub", "", "Subject")
		generateFlags.Var(&genAud, "aud", "Audience (repeatable)")
		generateFlags.StringVar(&genExp, "exp", "", "Expiration: duration or Unix timestamp")
		generateFlags.StringVar(&genNbf, "nbf", "", "Not before: duration or Unix timestamp")
		generateFlags.StringVar(&genIat, "iat", "", "Issued at: Unix timestamp")
		generateFlags.StringVar(&genJti, "jti", "", "JWT ID")
		generateFlags.StringVar(&genScope, "scope", "", "Scope claim")
		generateFlags.StringVar(&genNonce, "nonce", "", "Nonce claim")
		generateFlags.StringVar(&genAzp, "azp", "", "Authorized party")
		generateFlags.StringVar(&genAcr, "acr", "", "Auth context class reference")
		generateFlags.Var(&genClaims, "claim", "Arbitrary key=value claim (repeatable)")
		if err := generateFlags.Parse(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error parsing flags: %s\n", err)
			os.Exit(1)
		}
		modeFlag = modeGenerate
	} else if os.Args[1] == "jwks" {
		jwksFlags = flag.NewFlagSet("jwks", flag.ExitOnError)
		jwksFlags.Usage = func() { fmt.Print(jwksUsage) }
		jwksFlags.StringVar(&jwksIn, "in", "", "Input key file (PEM for RS/ES/EdDSA, certificate, or raw secret for HS*)")
		jwksFlags.StringVar(&jwksOut, "out", "", "Output JWKS file (defaults to stdout)")
		jwksFlags.StringVar(&jwksAlg, "alg", "", "Optional alg claim to set on each JWK")
		jwksFlags.StringVar(&jwksUse, "use", "", "Optional use (e.g., 'sig' or 'enc') to set on each JWK")
		jwksFlags.StringVar(&jwksKid, "kid", "", "Optional key ID to set (only valid for a single key)")
		jwksFlags.BoolVar(&jwksIncludePrivate, "private", false, "Include private key material when applicable (not recommended)")
		jwksFlags.BoolVar(&jwksUgly, "ugly", false, "Don't pretty print output JSON")
		jwksFlags.BoolVar(&jwksExt, "ext", false, "Set 'ext' (extractable) to true on each JWK")
		if err := jwksFlags.Parse(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error parsing flags: %s\n", err)
			os.Exit(1)
		}
		modeFlag = modeJWKS
	} else if os.Args[1] == "version" {
		modeFlag = modeVersion
	} else {
		flag.Parse()
	}
}

func main() {
	var err error
	switch modeFlag {
	case modeAssertion:
		if clientId == "" || audience == "" || privateKeyPath == "" {
			clientAssertionFlags.Usage()
			os.Exit(1)
		}
		err = assertion.Run(assertion.Config{
			ClientID:       clientId,
			Audience:       audience,
			PrivateKeyPath: privateKeyPath,
			Kid:            kid,
		}, os.Stdout, os.Stderr)
	case modeInspect:
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
			if scanErr := scanner.Err(); scanErr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Error reading from stdin: %s\n", scanErr)
				os.Exit(1)
			}
		}
		err = inspect.Run(inspect.Config{
			IncludeHeaders: includeHeaders,
			UglyPrint:      uglyPrint,
			VerifySig:      verifySig,
			VerifyKeyPath:  verifyKeyPath,
			JWKSRef:        jwksRef,
			Token:          jwtString,
		}, os.Stdout, os.Stderr)
	case modeJWKS:
		if jwksIn == "" {
			fmt.Fprintln(os.Stderr, "-in is required")
			jwksFlags.Usage()
			os.Exit(1)
		}
		err = jwks.Run(jwks.Config{
			InPath:    jwksIn,
			OutPath:   jwksOut,
			Alg:       jwksAlg,
			Use:       jwksUse,
			Kid:       jwksKid,
			Private:   jwksIncludePrivate,
			Ext:       jwksExt,
			UglyPrint: jwksUgly,
		}, os.Stdout, os.Stderr)
	case modeVersion:
		printVersion()
	case modeGenerate:
		if genAlg == "" || genKey == "" {
			_, _ = fmt.Fprintln(os.Stderr, "--alg and --key are required")
			generateFlags.Usage()
			os.Exit(1)
		}
		err = generate.Run(generate.Config{
			Alg:    genAlg,
			Key:    genKey,
			Kid:    genKid,
			Typ:    genTyp,
			Iss:    genIss,
			Sub:    genSub,
			Aud:    genAud,
			Exp:    genExp,
			Nbf:    genNbf,
			Iat:    genIat,
			Jti:    genJti,
			Scope:  genScope,
			Nonce:  genNonce,
			Azp:    genAzp,
			Acr:    genAcr,
			Claims: genClaims,
		}, os.Stdout, os.Stderr)
	}

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
