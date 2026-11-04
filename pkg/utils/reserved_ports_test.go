package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReservePort(t *testing.T) {
	for _, tc := range []struct {
		name, before, after string
	}{
		{"empty", "\n", "39400\n"},
		{"preserve", "30000-30010,40000\n", "30000-30010,40000,39400\n"},
		{"already reserved", "39400\n", "39400\n"},
		{"inside range", "39300-39500\n", "39300-39500\n"},
		{"range start", "39400-39500\n", "39400-39500\n"},
		{"range end", "39300-39400\n", "39300-39400\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reserved_ports")
			if err := os.WriteFile(path, []byte(tc.before), 0o600); err != nil {
				t.Fatal(err)
			}
			for range 2 { // A restart must not duplicate the reservation.
				if err := ReservePort(path, 39400); err != nil {
					t.Fatal(err)
				}
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != tc.after {
				t.Fatalf("got %q, %v; want %q", got, err, tc.after)
			}
		})
	}
}

func TestReservePortErrors(t *testing.T) {
	for _, value := range []string{"invalid", "40000-39000", "1-65536", "30000-", "30000,,40000"} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reserved_ports")
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ReservePort(path, 39400); err == nil {
				t.Fatal("expected malformed reservation to fail")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != value {
				t.Fatalf("malformed reservation was changed: %q, %v", got, err)
			}
		})
	}
	if err := ReservePort(filepath.Join(t.TempDir(), "missing"), 39400); err == nil {
		t.Fatal("expected read failure")
	}
	for _, port := range []int{0, -1, 65536} {
		if err := ReservePort("", port); err == nil {
			t.Fatalf("expected invalid port %d to fail", port)
		}
	}
}
