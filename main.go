package main

import "github.com/apisentry-dev/apisentry/cmd"

// version is set at build time via -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

func main() {
	cmd.SetVersion(version)
	cmd.Execute()
}
