package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/term"
	"os"
	"strings"
)

const usage = `usage: jwtool [JWT] [option...]
  --ugly           don't pretty-print the output
  -H, --headers    include JWT headers in output
  -h, --help       print this help and exit

JWT can also be piped through stdin:
  echo -n "jwt" | jwtool

For best effect, pipe output to jq to get syntax highlighting:
  jwtool "jwt" | jq
`

var includeHeaders bool
var uglyPrint bool

// TODO: Signature verification

func init() {
	flag.Usage = func() { fmt.Print(usage) }
	flag.BoolVar(&includeHeaders, "headers", false, "Output the header content of the JWT along with claims")
	flag.BoolVar(&includeHeaders, "H", false, "Output the headers content of the JWT")
	flag.BoolVar(&uglyPrint, "ugly", false, "Don't pretty print")
	flag.Parse()
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

func main() {
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

	token, err := jwt.Parse(jwtString, nil)
	if err != nil {
		if !errors.Is(err, jwt.ErrTokenUnverifiable) {
			_, _ = fmt.Fprintf(os.Stderr, "Error parsing JWT: %s\n", err)
			os.Exit(1)
		}
	}

	if includeHeaders {
		fmt.Println(format(token.Header))
	}
	fmt.Println(format(token.Claims))
}
