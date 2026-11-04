package utils

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReservePort excludes port from automatic source-port allocation in the network
// namespace represented by path (net.ipv4.ip_local_reserved_ports). Existing
// reservations are preserved. Explicit binds, including existing sockets, are
// unaffected. Callers must serialize changes with other writers of this sysctl.
func ReservePort(path string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid reserved port %d", port)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read reserved ports: %w", err)
	}
	current := strings.TrimSpace(string(data))
	if current != "" {
		for _, entry := range strings.Split(current, ",") {
			bounds := strings.SplitN(entry, "-", 2)
			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return fmt.Errorf("invalid reserved port entry %q", entry)
			}
			end := start
			if len(bounds) == 2 {
				end, err = strconv.Atoi(bounds[1])
				if err != nil {
					return fmt.Errorf("invalid reserved port entry %q", entry)
				}
			}
			if start < 1 || end > 65535 || end < start {
				return fmt.Errorf("invalid reserved port entry %q", entry)
			}
			if start <= port && port <= end {
				return nil
			}
		}
		current += ","
	}
	if err := os.WriteFile(path, []byte(current+strconv.Itoa(port)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write reserved ports: %w", err)
	}
	return nil
}
