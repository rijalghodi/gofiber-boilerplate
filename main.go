package main

import (
	"app/cmd"
	"log"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatalf("Could not execute command!, err: %s", err.Error())
	}
}
