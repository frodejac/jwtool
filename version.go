package main

import (
	"fmt"
	"runtime/debug"
)

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
