package atdid_test

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/reiver/go-atdid"
)

// readLines returns a fixture file's lines, without blank lines and "#" comments.
func readLines(t *testing.T, path string) []string {
	t.Helper()

	file, err := os.Open(path)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	defer file.Close()

	var lines []string
	var scanner *bufio.Scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		var line string = scanner.Text()
		if "" == strings.TrimSpace(line) || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if len(lines) < 1 {
		t.Fatalf("Expected some lines in %q, but there were none.", path)
	}
	return lines
}

func TestIsValid_interop(t *testing.T) {
	for _, did := range readLines(t, "testdata/did_syntax_valid.txt") {
		if !atdid.IsValid(did) {
			t.Errorf("Expected %q to be valid, but it was not.", did)
		}
	}

	for _, did := range readLines(t, "testdata/did_syntax_invalid.txt") {
		if atdid.IsValid(did) {
			t.Errorf("Expected %q to not be valid, but it was.", did)
		}
	}
}

func TestIsValid_length(t *testing.T) {
	var did string = "did:method:" + strings.Repeat("v", atdid.MaxLength-len("did:method:"))
	if !atdid.IsValid(did) {
		t.Errorf("Expected a %d-character DID to be valid, but it was not.", len(did))
	}
	if atdid.IsValid(did + "v") {
		t.Errorf("Expected a %d-character DID to not be valid, but it was.", len(did)+1)
	}
}

func TestIsPLC(t *testing.T) {
	tests := []struct {
		DID      string
		Expected bool
	}{
		{DID: "did:plc:ewvi7nxzyoun6zhxrhs64oiz", Expected: true},
		{DID: "did:plc:7iza6de2dwap2sbkpav7c6c6", Expected: true},
		{DID: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", Expected: true},
		{DID: "did:plc:222222222222222222222222", Expected: true},

		{DID: "did:plc:ewvi7nxzyoun6zhxrhs64oi", Expected: false},   // 23
		{DID: "did:plc:ewvi7nxzyoun6zhxrhs64oizz", Expected: false}, // 25
		{DID: "did:plc:Ewvi7nxzyoun6zhxrhs64oiz", Expected: false},  // upper-case
		{DID: "did:plc:ewvi1nxzyoun6zhxrhs64oiz", Expected: false},  // "1" is not base32
		{DID: "did:plc:ewvi8nxzyoun6zhxrhs64oiz", Expected: false},  // "8" is not base32
		{DID: "did:plc:ewvi7nxzyoun6zhxrhs64oi:", Expected: false},
		{DID: "did:PLC:ewvi7nxzyoun6zhxrhs64oiz", Expected: false},
		{DID: "did:web:ewvi7nxzyoun6zhxrhs64oiz", Expected: false},
		{DID: "", Expected: false},
	}

	for _, test := range tests {
		if actual := atdid.IsPLC(test.DID); test.Expected != actual {
			t.Errorf("For %q, expected %t but actually got %t.", test.DID, test.Expected, actual)
		}
	}
}

func TestIsWeb(t *testing.T) {
	tests := []struct {
		DID      string
		Expected bool
	}{
		{DID: "did:web:example.com", Expected: true},
		{DID: "did:web:mirror.example.com", Expected: true},
		{DID: "did:web:Example.COM", Expected: true},
		{DID: "did:web:xn--bcher-kva.example", Expected: true},
		{DID: "did:web:localhost", Expected: true},
		{DID: "did:web:localhost%3A1234", Expected: true},
		{DID: "did:web:localhost%3A65535", Expected: true},

		{DID: "did:web:example.com%3A8080", Expected: false},     // a port, not localhost
		{DID: "did:web:localhost%3A65536", Expected: false},      // not a port
		{DID: "did:web:localhost%3A", Expected: false},           // no port
		{DID: "did:web:localhost%3Ax", Expected: false},          // not a port
		{DID: "did:web:localhost%3a1234", Expected: false},       // only "%3A"
		{DID: "did:web:example.com:user:alice", Expected: false}, // a path
		{DID: "did:web:localhost:user", Expected: false},         // a path
		{DID: "did:web::example.com", Expected: false},
		{DID: "did:web:exa%6Dple.com", Expected: false},
		{DID: "did:web:", Expected: false},
		{DID: "did:web:example.com:", Expected: false},
		{DID: "did:plc:ewvi7nxzyoun6zhxrhs64oiz", Expected: false},
		{DID: "did:webs:example.com", Expected: false},
		{DID: "", Expected: false},
	}

	for _, test := range tests {
		if actual := atdid.IsWeb(test.DID); test.Expected != actual {
			t.Errorf("For %q, expected %t but actually got %t.", test.DID, test.Expected, actual)
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		DID      string
		Expected error
	}{
		{DID: "did:plc:ewvi7nxzyoun6zhxrhs64oiz", Expected: nil},
		{DID: "did:web:example.com", Expected: nil},
		{DID: "did:web:localhost%3A1234", Expected: nil},

		{DID: "did:plc:ewvi7nxzyoun6zhxrhs64oi", Expected: atdid.ErrBadDID},
		{DID: "did:web:example.com:user", Expected: atdid.ErrBadDID},
		{DID: "did:web:example.com%3A443", Expected: atdid.ErrBadDID},
		{DID: "did:key:zQ3shunBKsXixLxKtC5qeSG9E4J5RkGN57im31pcTzbNQnm5w", Expected: atdid.ErrUnsupportedMethod},
		{DID: "did:example:123456789abcdefghi", Expected: atdid.ErrUnsupportedMethod},
		{DID: "DID:plc:ewvi7nxzyoun6zhxrhs64oiz", Expected: atdid.ErrBadDID},
		{DID: "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz", Expected: atdid.ErrBadDID},
		{DID: "", Expected: atdid.ErrBadDID},
	}

	for _, test := range tests {
		err := atdid.Validate(test.DID)
		if nil == test.Expected {
			if nil != err {
				t.Errorf("For %q, did not expect an error but actually got one: (%T) %s", test.DID, err, err)
			}
			continue
		}
		if !errors.Is(err, test.Expected) {
			t.Errorf("For %q, expected an error wrapping %q but actually got: %v", test.DID, test.Expected, err)
		}
	}
}
