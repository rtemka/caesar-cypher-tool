package main

import (
	"CaesarCypher/src/caesarCypher"
	"os"
)

func main() {

	controller := caesarCypher.NewCaesarCypherController()

	exitCode := controller.Start()

	os.Exit(exitCode)
}
