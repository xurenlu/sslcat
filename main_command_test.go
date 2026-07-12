package main

import "testing"

func TestRejectUnexpectedPositionalArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "no arguments", args: nil},
		{name: "unknown command", args: []string{"reset-passwords"}, want: "unknown command or argument: reset-passwords"},
		{name: "extra argument", args: []string{"unexpected"}, want: "unknown command or argument: unexpected"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := rejectUnexpectedPositionalArguments(test.args)
			if test.want == "" {
				if err != nil {
					t.Fatalf("reject arguments: %v", err)
				}
				return
			}
			if err == nil || err.Error() != test.want {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
