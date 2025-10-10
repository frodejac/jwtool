# Repository Guidelines

This repository contains `jwtool`, a small Go CLI for inspecting and generating JSON Web Tokens (JWTs).

## Project Structure & Module Organization
- Root module with `go.mod`, source in `main.go` (single-binary CLI).
- Docs in `README.md`. License in `LICENSE`.
- If the project grows, prefer `cmd/jwtool/` for the entrypoint and `internal/` for shared packages.

## Build, Test, and Development Commands
- Build: `go build -o jwtool .` (outputs `./jwtool`).
- Run: `go run . --help` or `go run . <args>`.
- Install: `go install github.com/frodejac/jwtool@latest`.
- Format: `go fmt ./...` (required) and optionally `gofmt -s -w .`.
- Static checks: `go vet ./...`.
- Tests: `go test ./...` (add tests as `_test.go` alongside code).

## Coding Style & Naming Conventions
- Use `go fmt` defaults; do not commit unformatted code.
- Idiomatic Go: short variable names for limited scope, `err` for errors, early returns.
- Exported identifiers use `MixedCaps`; package-level unexported identifiers use `mixedCaps`.
- CLI flags mirror usage text; update both usage strings and README when adding flags.

## Testing Guidelines
- Framework: standard `testing` package; table-driven tests preferred.
- Location: place `*_test.go` files next to the code under test.
- Scope: cover JWT parsing, verification paths, and assertion claim construction.
- Run locally: `go test ./... -v`. No strict coverage threshold, but aim to exercise critical paths.

## Commit & Pull Request Guidelines
- Commits: short, imperative subject lines (e.g., "Add support for signature validation").
- PRs: include a clear description, linked issues, example commands, and any user-facing changes (flags, output). Update `README.md` if behavior changes.
- Keep diffs focused; avoid unrelated refactors in feature/fix PRs.

## Security & Configuration Tips
- Never commit private keys or secrets. Use temporary files in examples (e.g., `secret.key`, `private.pem`).
- Avoid logging sensitive JWTs; when necessary, redact.
- Verification keys: support PEM for RS/ES/EdDSA and raw bytes for HS*. Validate inputs and handle errors with context (e.g., `fmt.Errorf("read key: %w", err)`).

## Agent-Specific Instructions
- Keep changes minimal and consistent with existing patterns in `main.go`.
- After modifying flags or output, update usage text and `README.md` examples.
- Run `go fmt`, `go vet`, and relevant `go test` before opening a PR.
