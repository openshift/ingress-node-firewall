package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/mcuadros/go-syslog.v2"
)

// The daemon process logs events using Go's log/syslog package. That
// package, when using unix domain sockets, expects one of "/dev/log",
// "/var/run/syslog", or "/var/run/log" so we bind a matching path.
var listenAddress string = "/var/run/syslog"

func main() {
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC3164)
	server.SetHandler(handler)

	// check if syslog unix socket is already there then delete it.
	if _, err := os.Stat(listenAddress); err == nil {
		if err := os.Remove(listenAddress); err != nil {
			log.Fatalf("error removing syslog socket %s: %s", listenAddress, err)
		}
	}

	if err := server.ListenUnixgram(listenAddress); err != nil {
		log.Fatalf("failed to listen to syslog unix socket %s: %s", listenAddress, err)
	}

	defer func() {
		if err := os.Remove(listenAddress); err != nil {
			log.Fatalf("error removing syslog socket %s: %s", listenAddress, err)
		}
	}()

	if err := server.Boot(); err != nil {
		log.Fatalf("failed to boot syslog server: %s", err)
	}

	// Unix sockets must be unlink()ed before being reused again.
	// Handle common process-killing signals so we can gracefully shut down:
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(c chan os.Signal) {
		// Wait for a SIGINT or SIGKILL:
		sig := <-c
		log.Printf("Caught signal %s: shutting down.\n", sig)
		// Stop listening (and unlink the socket if unix type):
		if err := server.Kill(); err != nil {
			log.Fatalf("failed to close server connections: %s", err)
		}
	}(sigc)

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			fmt.Printf("%s %s %s\n", logParts["timestamp"], logParts["hostname"], logParts["content"])
		}
	}(channel)

	server.Wait()
}
