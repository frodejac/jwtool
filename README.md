# jwtool

Small, dead‑simple CLI for working with JSON Web Tokens (JWTs).

- Inspect a JWT and print its claims as JSON
- Optionally include the header
- Read the token from an argument or from stdin
- Generate a client assertion JWT (RS256) from an RSA private key

## Installation

Requires Go installed and configured.

```bash
go install github.com/frodejac/jwtool@latest
```

Or build from source in this repo:

```bash
go build -o jwtool .
```

## Usage

### Inspect JWTs

```
usage: jwtool [option...] [JWT]
  --ugly           don't pretty-print the output
  -H, --headers    include JWT headers in output
  -h, --help       print this help and exit
  --verify         verify the JWT signature
  --key            path to verification key (PEM for RS/ES/EdDSA, or raw secret file for HS*)
  --jwks           path or URL to JWKS (used with --verify)

Inspect a JWT and print its claims as JSON.

JWT can also be piped through stdin:
  echo -n "<jwt>" | jwtool

For best effect, pipe output to jq to get syntax highlighting:
  jwtool "<jwt>" | jq
```

Examples:

- From argument (pretty-printed by default):
  ```bash
  jwtool "$JWT" | jq
  ```

- Include headers (prints two JSON objects: header then claims):
  ```bash
  jwtool -H "$JWT"
  # Or combine and structure with jq:
  jwtool -H "$JWT" | jq -s '{headers: .[0], claims: .[1]}'
  ```

- From stdin:
  ```bash
  echo -n "$JWT" | jwtool
  ```

- Compact (no pretty-print):
  ```bash
  jwtool --ugly "$JWT"
  ```

Notes:
- Optional signature verification with `--verify` and `--key`. For RS/ES/EdDSA, `--key` should point to a PEM file containing a public (or private) key. For HS*, `--key` should point to a file containing the shared secret bytes.
- Alternatively, verify with a JWKS using `--jwks <path-or-url>`. If a URL is provided, the JWKS is fetched over HTTP(S). Key selection uses the token's `kid`; if no `kid` and the JWKS has multiple keys, verification fails.
- `--key` and `--jwks` are mutually exclusive.
- On malformed input, an error is printed to stderr and the program exits non‑zero.

Additional examples (verification):

- Verify signature (RS256 with PEM public key):
  ```bash
  # If you have a private key, you can extract the public key
  # openssl rsa -in private.pem -pubout -out pub.pem
  jwtool --verify --key pub.pem "$JWT"
  ```

- Verify signature (HS256 with shared secret in a file):
  ```bash
  printf 'super-secret' > secret.key
  jwtool --verify --key secret.key "$JWT"
  ```

- Verify via JWKS from a file:
  ```bash
  jwtool --verify --jwks jwks.json "$JWT"
  ```

- Verify via JWKS from a URL:
  ```bash
  jwtool --verify --jwks https://issuer.example.com/.well-known/jwks.json "$JWT"
  ```

### Generate Client Assertion

`jwtool` can generate a short‑lived client assertion JWT signed with an RSA private key (RS256). Claims include `iss`, `sub` (both set to the client ID), `aud`, `iat`, `nbf`, `exp` (now + 60s), and a random `jti`. The header `typ` is set to `client-authentication+jwt`.

```
usage: jwtool assertion [option...]
  --clientid, --client    Client ID (required)
  --audience, --aud      Audience (required)
  --privatekey, --key    Path to RSA private key in PEM format (required)
  -h, --help             print this help and exit
```

Examples:

1) Generate an RSA key if you don't already have one:
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
```

2) Create the client assertion (printed to stdout):
```bash
jwtool assertion \
  --clientid my-client-id \
  --audience https://issuer.example.com/oauth2/token \
  --key private.pem
```

You can use the resulting JWT as `client_assertion` in OAuth2/OpenID flows, e.g.:
```bash
curl -X POST https://issuer.example.com/oauth2/token \
  -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode client_assertion@<(jwtool assertion --clientid my-client-id --audience https://issuer.example.com/oauth2/token --key private.pem)
```

Flags and aliases:
- `--clientid` (alias `--client`)
- `--audience` (alias `--aud`)
- `--privatekey` (alias `--key`)

## Exit Codes

- `0` on success.
- Non‑zero on errors (invalid input, missing flags, IO/parse errors).

## License

This project is licensed under the terms of the LICENSE file in this repository.
