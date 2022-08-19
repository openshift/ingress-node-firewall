package main

import (
	"fmt"
	"log"

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

	if err := server.ListenUnixgram(listenAddress); err != nil {
		log.Fatal(err)
	}

	if err := server.Boot(); err != nil {
		log.Fatal(err)
	}

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			fmt.Printf("%s %s %s\n", logParts["timestamp"], logParts["hostname"], logParts["content"])
		}
	}(channel)

	server.Wait()
}
