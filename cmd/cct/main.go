package main

import (
	caesarCypher "cct/pkg/caesarcypher"
	"os"
)

func main() {

	controller := caesarCypher.NewCaesarCypherController()

	exitCode := controller.Start()

	os.Exit(exitCode)
}
