package main

import "testing"

func TestLocalHealthCheckHostPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		listen    string
		want      string
		expectErr bool
	}{
		{name: "empty host", listen: ":8080", want: "127.0.0.1:8080"},
		{name: "unspecified ipv4", listen: "0.0.0.0:8080", want: "127.0.0.1:8080"},
		{name: "unspecified ipv6", listen: "[::]:8080", want: "[::1]:8080"},
		{name: "specific ipv4", listen: "127.0.0.1:8080", want: "127.0.0.1:8080"},
		{name: "specific host", listen: "localhost:8080", want: "localhost:8080"},
		{name: "invalid", listen: "8080", expectErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := localHealthCheckHostPort(tt.listen)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
