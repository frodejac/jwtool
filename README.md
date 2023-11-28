# jwtool
Dead simple CLI tool for decoding JWTs

## Installation

```bash
go install github.com/frodejac/jwtool@latest
```

## Usage
```
usage: jwtool [JWT] [option...]
  --ugly           don't pretty-print the output
  -H, --headers    include JWT headers in output
  -h, --help       print this help and exit

JWT can also be piped through stdin:
  echo -n "jwt" | jwtool

For best effect, pipe output to jq to get syntax highlighting:
  jwtool "jwt" | jq
```