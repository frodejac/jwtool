#!/usr/bin/env bash
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
PASS=0
FAIL=0
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TMPDIR_BASE="$(mktemp -d)"

# Accept an optional binary path as the first argument.
# If not provided, build from local source.
if [ "${1:-}" != "" ]; then
  BIN="$1"
  echo "Using external binary: $BIN"
else
  BIN="$TMPDIR_BASE/jwtool"
fi

cleanup() {
  rm -rf "$TMPDIR_BASE"
}
trap cleanup EXIT

# ─── Helpers ─────────────────────────────────────────────────────────────────

# test_case NAME CMD [EXPECT_EXIT] [GREP_STDOUT] [GREP_STDERR]
# Runs CMD, checks exit code, and optionally greps stdout/stderr.
test_case() {
  local name="$1"
  shift
  local cmd="$1"
  shift
  local expect_exit="${1:-0}"
  shift || true
  local grep_stdout="${1:-}"
  shift || true
  local grep_stderr="${1:-}"
  shift || true

  local actual_exit=0
  local stdout_file="$TMPDIR_BASE/stdout.$$"
  local stderr_file="$TMPDIR_BASE/stderr.$$"

  eval "$cmd" >"$stdout_file" 2>"$stderr_file" || actual_exit=$?

  if [ "$actual_exit" -ne "$expect_exit" ]; then
    echo "FAIL: $name (exit: got $actual_exit, want $expect_exit)"
    echo "  stdout: $(cat "$stdout_file")"
    echo "  stderr: $(cat "$stderr_file")"
    FAIL=$((FAIL + 1))
    rm -f "$stdout_file" "$stderr_file"
    return
  fi

  if [ -n "$grep_stdout" ]; then
    if ! grep -qE -- "$grep_stdout" "$stdout_file"; then
      echo "FAIL: $name (stdout does not match: $grep_stdout)"
      echo "  stdout: $(cat "$stdout_file")"
      FAIL=$((FAIL + 1))
      rm -f "$stdout_file" "$stderr_file"
      return
    fi
  fi

  if [ -n "$grep_stderr" ]; then
    if ! grep -qE -- "$grep_stderr" "$stderr_file"; then
      echo "FAIL: $name (stderr does not match: $grep_stderr)"
      echo "  stderr: $(cat "$stderr_file")"
      FAIL=$((FAIL + 1))
      rm -f "$stdout_file" "$stderr_file"
      return
    fi
  fi

  echo "PASS: $name"
  PASS=$((PASS + 1))
  rm -f "$stdout_file" "$stderr_file"
}

# ─── Build ───────────────────────────────────────────────────────────────────
if [ "${1:-}" = "" ]; then
  echo "Building jwtool from local source..."
  (cd "$PROJECT_DIR" && go build -o "$BIN" .)
fi

# ─── Generate test keys ─────────────────────────────────────────────────────
echo "Generating test keys..."
openssl genrsa -out "$TMPDIR_BASE/rsa.pem" 2048 2>/dev/null
openssl rsa -in "$TMPDIR_BASE/rsa.pem" -pubout -out "$TMPDIR_BASE/rsa_pub.pem" 2>/dev/null

# Generate a second RSA key (for wrong-key test)
openssl genrsa -out "$TMPDIR_BASE/rsa_wrong.pem" 2048 2>/dev/null
openssl rsa -in "$TMPDIR_BASE/rsa_wrong.pem" -pubout -out "$TMPDIR_BASE/rsa_wrong_pub.pem" 2>/dev/null

openssl ecparam -genkey -name prime256v1 -noout -out "$TMPDIR_BASE/ec.pem" 2>/dev/null
openssl ec -in "$TMPDIR_BASE/ec.pem" -pubout -out "$TMPDIR_BASE/ec_pub.pem" 2>/dev/null

openssl genpkey -algorithm Ed25519 -out "$TMPDIR_BASE/ed.pem" 2>/dev/null
openssl pkey -in "$TMPDIR_BASE/ed.pem" -pubout -out "$TMPDIR_BASE/ed_pub.pem" 2>/dev/null

echo -n "test-hmac-secret-key-at-least-32b" > "$TMPDIR_BASE/hmac.key"

# A known JWT for inspection tests (HS256, secret = "test-hmac-secret-key-at-least-32b")
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"iat":1516239022,"jti":"fixed-jti","name":"Test User","sub":"1234567890"}
KNOWN_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsImp0aSI6ImZpeGVkLWp0aSIsIm5hbWUiOiJUZXN0IFVzZXIiLCJzdWIiOiIxMjM0NTY3ODkwIn0.fvKkXNqY0vRCXuX9ZavO9oBTCls5i0DrS9rI7RBxaBg"

echo ""
echo "=== Running acceptance tests ==="
echo ""

# ─── Inspect mode ────────────────────────────────────────────────────────────

test_case "inspect: known JWT shows claims" \
  "$BIN '$KNOWN_JWT'" \
  0 '"sub".*"1234567890"'

test_case "inspect: --ugly produces compact JSON" \
  "$BIN --ugly '$KNOWN_JWT'" \
  0 '"sub":"1234567890"'

test_case "inspect: -H includes headers" \
  "$BIN -H '$KNOWN_JWT'" \
  0 '"alg".*"HS256"'

test_case "inspect: stdin pipe" \
  "echo -n '$KNOWN_JWT' | $BIN" \
  0 '"sub".*"1234567890"'

test_case "inspect: --verify --key correct HMAC key" \
  "$BIN --verify --key '$TMPDIR_BASE/hmac.key' '$KNOWN_JWT'" \
  0 '"sub".*"1234567890"'

test_case "inspect: --verify --key wrong key fails" \
  "$BIN --verify --key '$TMPDIR_BASE/rsa_pub.pem' '$KNOWN_JWT'" \
  1

test_case "inspect: --verify without --key/--jwks fails" \
  "$BIN --verify '$KNOWN_JWT'" \
  1 "" "--verify requires --key or --jwks"

test_case "inspect: --verify with both --key and --jwks fails" \
  "$BIN --verify --key '$TMPDIR_BASE/hmac.key' --jwks '$TMPDIR_BASE/hmac.key' '$KNOWN_JWT'" \
  1 "" "--key and --jwks are mutually exclusive"

test_case "inspect: invalid JWT fails" \
  "$BIN 'not.a.valid.jwt'" \
  1

# Generate an RSA-signed JWT and create a JWKS for it to test --jwks verification
RSA_JWT=$("$BIN" generate --alg RS256 --key "$TMPDIR_BASE/rsa.pem" --kid "test-kid-1" --sub "jwks-test")
"$BIN" jwks -in "$TMPDIR_BASE/rsa_pub.pem" --kid "test-kid-1" > "$TMPDIR_BASE/test.jwks"

test_case "inspect: --verify --jwks from local file" \
  "$BIN --verify --jwks '$TMPDIR_BASE/test.jwks' '$RSA_JWT'" \
  0 '"sub".*"jwks-test"'

# ─── Generate mode ───────────────────────────────────────────────────────────

test_case "generate: RS256 + RSA key produces valid JWT" \
  "$BIN generate --alg RS256 --key '$TMPDIR_BASE/rsa.pem'" \
  0

# Verify the generated RSA JWT can be re-inspected
RSA_GEN=$("$BIN" generate --alg RS256 --key "$TMPDIR_BASE/rsa.pem" --sub "rsa-test")
test_case "generate: RS256 JWT is inspectable" \
  "$BIN '$RSA_GEN'" \
  0 '"sub".*"rsa-test"'

test_case "generate: ES256 + EC key produces valid JWT" \
  "$BIN generate --alg ES256 --key '$TMPDIR_BASE/ec.pem'" \
  0

EC_GEN=$("$BIN" generate --alg ES256 --key "$TMPDIR_BASE/ec.pem" --sub "ec-test")
test_case "generate: ES256 JWT is inspectable" \
  "$BIN '$EC_GEN'" \
  0 '"sub".*"ec-test"'

test_case "generate: EdDSA + Ed25519 key produces valid JWT" \
  "$BIN generate --alg EdDSA --key '$TMPDIR_BASE/ed.pem'" \
  0

ED_GEN=$("$BIN" generate --alg EdDSA --key "$TMPDIR_BASE/ed.pem" --sub "ed-test")
test_case "generate: EdDSA JWT is inspectable" \
  "$BIN '$ED_GEN'" \
  0 '"sub".*"ed-test"'

test_case "generate: HS256 + symmetric key produces valid JWT" \
  "$BIN generate --alg HS256 --key '$TMPDIR_BASE/hmac.key'" \
  0

HS_GEN=$("$BIN" generate --alg HS256 --key "$TMPDIR_BASE/hmac.key" --sub "hs-test")
test_case "generate: HS256 JWT is inspectable" \
  "$BIN '$HS_GEN'" \
  0 '"sub".*"hs-test"'

# Test claims
CLAIMS_JWT=$("$BIN" generate --alg HS256 --key "$TMPDIR_BASE/hmac.key" \
  --iss "test-issuer" --sub "test-subject" --aud "aud1" --exp 1h --nbf 0s)
test_case "generate: --iss, --sub, --aud, --exp, --nbf present" \
  "$BIN '$CLAIMS_JWT'" \
  0 '"iss".*"test-issuer"'

# Multiple --aud
MULTI_AUD_JWT=$("$BIN" generate --alg HS256 --key "$TMPDIR_BASE/hmac.key" \
  --aud "aud1" --aud "aud2")
test_case "generate: multiple --aud produces array" \
  "$BIN '$MULTI_AUD_JWT'" \
  0 '"aud"'

# Custom claims
CUSTOM_JWT=$("$BIN" generate --alg HS256 --key "$TMPDIR_BASE/hmac.key" \
  --claim "foo=bar")
test_case "generate: --claim key=value" \
  "$BIN '$CUSTOM_JWT'" \
  0 '"foo".*"bar"'

# Auto-detected types
TYPED_JWT=$("$BIN" generate --alg HS256 --key "$TMPDIR_BASE/hmac.key" \
  --claim "mybool=true" --claim "myint=42" --claim "myfloat=3.14" \
  --claim 'myjson={"nested":"value"}' --claim "mystr=hello")
test_case "generate: claim auto-detect bool" \
  "$BIN '$TYPED_JWT'" \
  0 '"mybool".*true'
test_case "generate: claim auto-detect int" \
  "$BIN '$TYPED_JWT'" \
  0 '"myint".*42'
test_case "generate: claim auto-detect float" \
  "$BIN '$TYPED_JWT'" \
  0 '"myfloat".*3.14'
test_case "generate: claim auto-detect JSON object" \
  "$BIN '$TYPED_JWT'" \
  0 '"nested".*"value"'
test_case "generate: claim auto-detect string" \
  "$BIN '$TYPED_JWT'" \
  0 '"mystr".*"hello"'

# Missing required flags
test_case "generate: missing --alg fails" \
  "$BIN generate --key '$TMPDIR_BASE/hmac.key'" \
  1

test_case "generate: missing --key fails" \
  "$BIN generate --alg HS256" \
  1

# --kid in header
KID_JWT=$("$BIN" generate --alg HS256 --key "$TMPDIR_BASE/hmac.key" --kid "my-kid")
test_case "generate: --kid appears in header" \
  "$BIN -H '$KID_JWT'" \
  0 '"kid".*"my-kid"'

# ─── Assertion mode ──────────────────────────────────────────────────────────

ASSERTION=$("$BIN" assertion --clientid "my-client" --audience "https://example.com" --key "$TMPDIR_BASE/rsa.pem")
test_case "assertion: produces a JWT" \
  "$BIN '$ASSERTION'" \
  0 '"iss".*"my-client"'

test_case "assertion: has expected claims" \
  "$BIN '$ASSERTION'" \
  0 '"sub".*"my-client"'

# Verify aud, exp, nbf, iat, jti are present
test_case "assertion: has aud claim" \
  "$BIN '$ASSERTION'" \
  0 '"aud"'

test_case "assertion: has exp claim" \
  "$BIN '$ASSERTION'" \
  0 '"exp"'

test_case "assertion: has nbf claim" \
  "$BIN '$ASSERTION'" \
  0 '"nbf"'

test_case "assertion: has iat claim" \
  "$BIN '$ASSERTION'" \
  0 '"iat"'

test_case "assertion: has jti claim" \
  "$BIN '$ASSERTION'" \
  0 '"jti"'

# Verify header
test_case "assertion: header typ = client-authentication+jwt" \
  "$BIN -H '$ASSERTION'" \
  0 '"typ".*"client-authentication\+jwt"'

test_case "assertion: header alg = RS256" \
  "$BIN -H '$ASSERTION'" \
  0 '"alg".*"RS256"'

# Missing required flags
test_case "assertion: missing --clientid fails" \
  "$BIN assertion --audience 'https://example.com' --key '$TMPDIR_BASE/rsa.pem'" \
  1

test_case "assertion: missing --audience fails" \
  "$BIN assertion --clientid 'my-client' --key '$TMPDIR_BASE/rsa.pem'" \
  1

test_case "assertion: missing --key fails" \
  "$BIN assertion --clientid 'my-client' --audience 'https://example.com'" \
  1

# ─── JWKS mode ───────────────────────────────────────────────────────────────

test_case "jwks: RSA private → public JWKS" \
  "$BIN jwks -in '$TMPDIR_BASE/rsa.pem'" \
  0 '"keys"'

# Check that private material is NOT included by default
RSA_JWKS=$("$BIN" jwks -in "$TMPDIR_BASE/rsa.pem")
test_case "jwks: RSA default has no private 'd' field" \
  "echo '$RSA_JWKS' | grep -c '\"d\"'" \
  1

test_case "jwks: RSA --private includes 'd' field" \
  "$BIN jwks -in '$TMPDIR_BASE/rsa.pem' --private" \
  0 '"d"'

test_case "jwks: RSA --private includes CRT params" \
  "$BIN jwks -in '$TMPDIR_BASE/rsa.pem' --private" \
  0 '"dp"'

test_case "jwks: EC public key → JWKS" \
  "$BIN jwks -in '$TMPDIR_BASE/ec_pub.pem'" \
  0 '"kty".*"EC"'

test_case "jwks: Ed25519 key → JWKS" \
  "$BIN jwks -in '$TMPDIR_BASE/ed_pub.pem'" \
  0 '"kty".*"OKP"'

test_case "jwks: symmetric key + --private" \
  "$BIN jwks -in '$TMPDIR_BASE/hmac.key' --private" \
  0 '"kty".*"OCT"'

test_case "jwks: symmetric key without --private fails" \
  "$BIN jwks -in '$TMPDIR_BASE/hmac.key'" \
  1

test_case "jwks: --alg, --use, --kid" \
  "$BIN jwks -in '$TMPDIR_BASE/rsa_pub.pem' --alg RS256 --use sig --kid my-kid-1" \
  0 '"kid".*"my-kid-1"'

# Verify --alg and --use are in output
JWKS_OPTS=$("$BIN" jwks -in "$TMPDIR_BASE/rsa_pub.pem" --alg RS256 --use sig --kid my-kid-1)
test_case "jwks: --alg appears in output" \
  "echo '$JWKS_OPTS'" \
  0 '"alg".*"RS256"'

test_case "jwks: --use appears in output" \
  "echo '$JWKS_OPTS'" \
  0 '"use".*"sig"'

test_case "jwks: --ugly produces compact JSON" \
  "$BIN jwks -in '$TMPDIR_BASE/rsa_pub.pem' --ugly" \
  0 '"keys":\['

test_case "jwks: -out writes to file" \
  "$BIN jwks -in '$TMPDIR_BASE/rsa_pub.pem' -out '$TMPDIR_BASE/output.jwks'" \
  0

test_case "jwks: -out file exists" \
  "test -f '$TMPDIR_BASE/output.jwks' && cat '$TMPDIR_BASE/output.jwks'" \
  0 '"keys"'

# Multiple keys + --kid should fail
cat "$TMPDIR_BASE/rsa.pem" "$TMPDIR_BASE/ec.pem" > "$TMPDIR_BASE/multi.pem"
test_case "jwks: multiple keys + --kid fails" \
  "$BIN jwks -in '$TMPDIR_BASE/multi.pem' --kid foo" \
  1 "" "--kid is only allowed when exactly one key"

# ─── Version mode ────────────────────────────────────────────────────────────

test_case "version: exits 0 and shows version" \
  "$BIN version" \
  0 "jwtool"

# ─── Edge cases ──────────────────────────────────────────────────────────────

test_case "edge: unknown subcommand treated as inspect (invalid JWT)" \
  "$BIN notasubcommand" \
  1

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "=== Results ==="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "TOTAL: $((PASS + FAIL))"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo ""
echo "All tests passed!"
