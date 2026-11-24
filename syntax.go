package atdid

import (
	"strconv"
	"strings"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"
)

// MaxLength is the longest a DID may be, in ATProto.
const MaxLength = 2048

const (
	PrefixPLC = "did:plc:"
	PrefixWeb = "did:web:"
)

const plcLength = len(PrefixPLC) + 24

// localhostPortPrefix is how a did:web for localhost gives a port ("%3A" is an encoded ":").
const localhostPortPrefix = "localhost%3A"

// IsValid returns whether 'did' has ATProto's DID syntax — with any DID method.
//
// That is: "did:", a method of lower-case letters, ":", then one or more of [a-zA-Z0-9._:%-], not ending in ":" or "%"; at most [MaxLength] characters.
// (Percent-encoding is not checked.)
//
// See also [Validate], which also requires one of the DID methods ATProto allows.
func IsValid(did string) bool {
	if MaxLength < len(did) {
		return false
	}

	rest, found := strings.CutPrefix(did, "did:")
	if !found {
		return false
	}

	method, msid, found := strings.Cut(rest, ":")
	if !found || "" == method || "" == msid {
		return false
	}

	for index := 0; index < len(method); index++ {
		var c byte = method[index]
		if c < 'a' || 'z' < c {
			return false
		}
	}

	for index := 0; index < len(msid); index++ {
		var c byte = msid[index]
		switch {
		case 'a' <= c && c <= 'z':
		case 'A' <= c && c <= 'Z':
		case '0' <= c && c <= '9':
		case '.' == c, '_' == c, ':' == c, '%' == c, '-' == c:
		default:
			return false
		}
	}

	switch msid[len(msid)-1] {
	case ':', '%':
		return false
	}

	return true
}

// IsPLC returns whether 'did' is a did:plc — "did:plc:" then 24 characters of [a-z2-7].
func IsPLC(did string) bool {
	if plcLength != len(did) {
		return false
	}
	if !strings.HasPrefix(did, PrefixPLC) {
		return false
	}

	for index := len(PrefixPLC); index < len(did); index++ {
		var c byte = did[index]
		switch {
		case 'a' <= c && c <= 'z':
		case '2' <= c && c <= '7':
		default:
			return false
		}
	}

	return true
}

// IsWeb returns whether 'did' is a did:web that ATProto allows — a hostname only (ex: "did:web:example.com").
//
// ATProto does not allow paths. And it allows a port (ex: "did:web:localhost%3A8080") only for localhost.
func IsWeb(did string) bool {
	if !IsValid(did) {
		return false
	}

	msid, found := strings.CutPrefix(did, PrefixWeb)
	if !found {
		return false
	}

	if port, found := strings.CutPrefix(msid, localhostPortPrefix); found {
		return isPort(port)
	}

	for index := 0; index < len(msid); index++ {
		var c byte = msid[index]
		switch {
		case 'a' <= c && c <= 'z':
		case 'A' <= c && c <= 'Z':
		case '0' <= c && c <= '9':
		case '.' == c, '_' == c, '-' == c:
		default:
			return false
		}
	}

	return true
}

func isPort(s string) bool {
	if "" == s || 5 < len(s) {
		return false
	}
	for index := 0; index < len(s); index++ {
		if s[index] < '0' || '9' < s[index] {
			return false
		}
	}

	port, err := strconv.Atoi(s)
	return nil == err && port <= 65535
}

// Validate returns an error unless 'did' is a valid DID whose DID method ATProto allows — a did:plc (see [IsPLC]) or a did:web (see [IsWeb]).
func Validate(did string) error {
	if !IsValid(did) {
		return erorr.Wrap(ErrBadDID, "bad DID syntax", field.String("did", did))
	}

	switch {
	case strings.HasPrefix(did, PrefixPLC):
		if !IsPLC(did) {
			return erorr.Wrap(ErrBadDID, "bad did:plc — must be \"did:plc:\" then 24 characters of [a-z2-7]", field.String("did", did))
		}
	case strings.HasPrefix(did, PrefixWeb):
		if !IsWeb(did) {
			return erorr.Wrap(ErrBadDID, "bad did:web — must be a hostname only (a port only for localhost)", field.String("did", did))
		}
	default:
		return erorr.Wrap(ErrUnsupportedMethod, "unsupported DID method", field.String("did", did))
	}

	return nil
}

// webDocumentURL returns where a did:web's DID document is — "https://<host>/.well-known/did.json" (or "http://" for localhost).
//
// 'did' must already have passed [IsWeb].
func webDocumentURL(did string) string {
	var host string = strings.Replace(strings.TrimPrefix(did, PrefixWeb), "%3A", ":", 1)

	var scheme string = "https"
	if "localhost" == host || strings.HasPrefix(host, "localhost:") {
		scheme = "http"
	}

	return scheme + "://" + host + "/.well-known/did.json"
}
