package atdid_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/reiver/go-did"
	"github.com/reiver/go-didkey"

	"github.com/reiver/go-atdid"
	"github.com/reiver/go-atdid/internal/base58"
)

const testDID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"

// secp256k1Multikey is the "#atproto" key of testdata/did_plc_ewvi7nxzyoun6zhxrhs64oiz.json.
const secp256k1Multikey = "zQ3shunBKsXixLxKtC5qeSG9E4J5RkGN57im31pcTzbNQnm5w"

func mustParseDocument(t *testing.T, data string) did.Document {
	t.Helper()

	document, err := did.ParseDocument([]byte(data))
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s\n%s", err, err, data)
	}
	return document
}

// documentWith returns a DID document (for testDID) with the given JSON for its "verificationMethod" and "service".
func documentWith(t *testing.T, verificationMethods string, services string) did.Document {
	t.Helper()

	return mustParseDocument(t, fmt.Sprintf(`{"id":%q,"verificationMethod":[%s],"service":[%s]}`, testDID, verificationMethods, services))
}

func verificationMethod(id string, typ string, multibase string) string {
	return fmt.Sprintf(`{"id":%q,"type":%q,"controller":%q,"publicKeyMultibase":%q}`, id, typ, testDID, multibase)
}

func newP256Key(t *testing.T) didkey.PublicKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	public, err := didkey.FromECDSA(&key.PublicKey)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	return public
}

func mustParseMultikey(t *testing.T, multikey string) didkey.PublicKey {
	t.Helper()

	key, err := didkey.ParseMultikey(multikey)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	return key
}

func legacyMultibase(p []byte) string {
	return "z" + base58.Encode(p)
}

func TestRealDocument(t *testing.T) {
	data, err := os.ReadFile("testdata/did_plc_ewvi7nxzyoun6zhxrhs64oiz.json")
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	document := mustParseDocument(t, string(data))

	key, err := atdid.SigningKey(document)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if expected := mustParseMultikey(t, secp256k1Multikey); !expected.Equal(key) {
		t.Errorf("Expected the signing key %s but actually got %s.", expected, key)
	}
	if didkey.KeyTypeSecp256k1 != key.Type() {
		t.Errorf("Expected a secp256k1 key but actually got %q.", key.Type())
	}

	endpoint, err := atdid.PDSEndpoint(document)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if expected := "https://enoki.us-east.host.bsky.network"; expected != endpoint {
		t.Errorf("Expected the PDS endpoint %q but actually got %q.", expected, endpoint)
	}

	handle, found := atdid.Handle(document)
	if !found || "atproto.com" != handle {
		t.Errorf("Expected the handle %q but actually got %q (found=%t).", "atproto.com", handle, found)
	}

	if _, err := atdid.KEMKey(document); !errors.Is(err, atdid.ErrKeyNotFound) {
		t.Errorf("Expected an error wrapping %q but actually got: %v", atdid.ErrKeyNotFound, err)
	}
}

func TestSigningKey(t *testing.T) {
	var p256 didkey.PublicKey = newP256Key(t)
	var k256 didkey.PublicKey = mustParseMultikey(t, secp256k1Multikey)

	tests := []struct {
		Name     string
		Method   string
		Expected didkey.PublicKey
	}{
		{Name: "Multikey P-256", Method: verificationMethod("#atproto", atdid.TypeMultikey, p256.Multikey()), Expected: p256},
		{Name: "Multikey secp256k1", Method: verificationMethod("#atproto", atdid.TypeMultikey, k256.Multikey()), Expected: k256},
		{Name: "absolute id", Method: verificationMethod(testDID+"#atproto", atdid.TypeMultikey, p256.Multikey()), Expected: p256},
		{Name: "legacy P-256 compressed", Method: verificationMethod("#atproto", atdid.TypeEcdsaSecp256r1VerificationKey2019, legacyMultibase(p256.Compressed())), Expected: p256},
		{Name: "legacy P-256 uncompressed", Method: verificationMethod("#atproto", atdid.TypeEcdsaSecp256r1VerificationKey2019, legacyMultibase(p256.Uncompressed())), Expected: p256},
		{Name: "legacy secp256k1 compressed", Method: verificationMethod("#atproto", atdid.TypeEcdsaSecp256k1VerificationKey2019, legacyMultibase(k256.Compressed())), Expected: k256},
		{Name: "legacy secp256k1 uncompressed", Method: verificationMethod("#atproto", atdid.TypeEcdsaSecp256k1VerificationKey2019, legacyMultibase(k256.Uncompressed())), Expected: k256},
	}

	for _, test := range tests {
		// Another key comes first, to check the right one is found.
		var other string = verificationMethod("#other", atdid.TypeMultikey, newP256Key(t).Multikey())
		document := documentWith(t, other+","+test.Method, "")

		key, err := atdid.SigningKey(document)
		if nil != err {
			t.Errorf("For %s, did not expect an error but actually got one: (%T) %s", test.Name, err, err)
			continue
		}
		if !test.Expected.Equal(key) {
			t.Errorf("For %s, expected the key %s but actually got %s.", test.Name, test.Expected, key)
		}
	}
}

func TestSigningKey_errors(t *testing.T) {
	var p256 didkey.PublicKey = newP256Key(t)
	var k256 didkey.PublicKey = mustParseMultikey(t, secp256k1Multikey)

	// An uncompressed point whose y is wrong (its parity is unchanged, so its compressed form is still a valid point).
	var badY []byte = bytes.Clone(k256.Uncompressed())
	badY[64] ^= 0x02

	// An uncompressed point whose y has the wrong parity.
	var badParity []byte = bytes.Clone(k256.Uncompressed())
	badParity[64] ^= 0x01

	tests := []struct {
		Name     string
		Methods  string
		Expected error
	}{
		{Name: "none", Methods: "", Expected: atdid.ErrKeyNotFound},
		{Name: "other id", Methods: verificationMethod("#atproto_kem", atdid.TypeMultikey, p256.Multikey()), Expected: atdid.ErrKeyNotFound},
		{Name: "other DID", Methods: verificationMethod("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#atproto", atdid.TypeMultikey, p256.Multikey()), Expected: atdid.ErrKeyNotFound},
		{Name: "no multibase", Methods: fmt.Sprintf(`{"id":"#atproto","type":"Multikey","controller":%q}`, testDID), Expected: atdid.ErrBadKey},
		{Name: "unsupported type", Methods: verificationMethod("#atproto", "JsonWebKey2020", p256.Multikey()), Expected: atdid.ErrBadKey},
		{Name: "bad Multikey", Methods: verificationMethod("#atproto", atdid.TypeMultikey, "zBAD"), Expected: atdid.ErrBadKey},
		{Name: "legacy not base58btc", Methods: verificationMethod("#atproto", atdid.TypeEcdsaSecp256r1VerificationKey2019, "f"+fmt.Sprintf("%x", p256.Compressed())), Expected: atdid.ErrBadKey},
		{Name: "legacy bad base58", Methods: verificationMethod("#atproto", atdid.TypeEcdsaSecp256r1VerificationKey2019, "z0OIl"), Expected: atdid.ErrBadKey},
		{Name: "legacy short", Methods: verificationMethod("#atproto", atdid.TypeEcdsaSecp256r1VerificationKey2019, legacyMultibase(p256.Compressed()[:32])), Expected: atdid.ErrBadKey},
		{Name: "legacy 65 bytes not 0x04", Methods: verificationMethod("#atproto", atdid.TypeEcdsaSecp256k1VerificationKey2019, legacyMultibase(append([]byte{0x05}, k256.Uncompressed()[1:]...))), Expected: atdid.ErrBadKey},
		{Name: "legacy wrong y", Methods: verificationMethod("#atproto", atdid.TypeEcdsaSecp256k1VerificationKey2019, legacyMultibase(badY)), Expected: atdid.ErrBadKey},
		{Name: "legacy wrong y parity", Methods: verificationMethod("#atproto", atdid.TypeEcdsaSecp256k1VerificationKey2019, legacyMultibase(badParity)), Expected: atdid.ErrBadKey},
		{Name: "legacy Multikey bytes", Methods: verificationMethod("#atproto", atdid.TypeEcdsaSecp256k1VerificationKey2019, k256.Multikey()), Expected: atdid.ErrBadKey},
	}

	for _, test := range tests {
		document := documentWith(t, test.Methods, "")

		_, err := atdid.SigningKey(document)
		if !errors.Is(err, test.Expected) {
			t.Errorf("For %s, expected an error wrapping %q but actually got: %v", test.Name, test.Expected, err)
		}
	}
}

func TestKEMKey(t *testing.T) {
	var p256 didkey.PublicKey = newP256Key(t)
	var k256 didkey.PublicKey = mustParseMultikey(t, secp256k1Multikey)
	var signing string = verificationMethod("#atproto", atdid.TypeMultikey, k256.Multikey())

	tests := []struct {
		Name     string
		Methods  string
		Expected error
	}{
		{Name: "Multikey P-256", Methods: signing + "," + verificationMethod("#atproto_kem", atdid.TypeMultikey, p256.Multikey()), Expected: nil},
		{Name: "absolute id", Methods: signing + "," + verificationMethod(testDID+"#atproto_kem", atdid.TypeMultikey, p256.Multikey()), Expected: nil},
		{Name: "legacy P-256", Methods: signing + "," + verificationMethod("#atproto_kem", atdid.TypeEcdsaSecp256r1VerificationKey2019, legacyMultibase(p256.Compressed())), Expected: nil},

		{Name: "none", Methods: signing, Expected: atdid.ErrKeyNotFound},
		{Name: "Multikey secp256k1", Methods: verificationMethod("#atproto_kem", atdid.TypeMultikey, k256.Multikey()), Expected: atdid.ErrBadKey},
		{Name: "legacy secp256k1", Methods: verificationMethod("#atproto_kem", atdid.TypeEcdsaSecp256k1VerificationKey2019, legacyMultibase(k256.Compressed())), Expected: atdid.ErrBadKey},
		{Name: "bad key", Methods: verificationMethod("#atproto_kem", atdid.TypeMultikey, "zBAD"), Expected: atdid.ErrBadKey},
	}

	for _, test := range tests {
		document := documentWith(t, test.Methods, "")

		key, err := atdid.KEMKey(document)
		if nil == test.Expected {
			if nil != err {
				t.Errorf("For %s, did not expect an error but actually got one: (%T) %s", test.Name, err, err)
				continue
			}
			if !p256.Equal(key) {
				t.Errorf("For %s, expected the key %s but actually got %s.", test.Name, p256, key)
			}
			continue
		}
		if !errors.Is(err, test.Expected) {
			t.Errorf("For %s, expected an error wrapping %q but actually got: %v", test.Name, test.Expected, err)
		}
	}
}

func TestPDSEndpoint(t *testing.T) {
	service := func(id string, typ string, endpoint string) string {
		return fmt.Sprintf(`{"id":%q,"type":%q,"serviceEndpoint":%s}`, id, typ, endpoint)
	}

	tests := []struct {
		Name     string
		Services string
		Expected string
		Error    error
	}{
		{Name: "https", Services: service("#atproto_pds", atdid.ServiceTypePDS, `"https://pds.example.com"`), Expected: "https://pds.example.com"},
		{Name: "http with port", Services: service("#atproto_pds", atdid.ServiceTypePDS, `"http://localhost:2583"`), Expected: "http://localhost:2583"},
		{Name: "absolute id", Services: service(testDID+"#atproto_pds", atdid.ServiceTypePDS, `"https://pds.example.com"`), Expected: "https://pds.example.com"},
		{Name: "after another", Services: service("#bsky_fg", "BskyFeedGenerator", `"https://feed.example.com"`) + "," + service("#atproto_pds", atdid.ServiceTypePDS, `"https://pds.example.com"`), Expected: "https://pds.example.com"},

		{Name: "none", Services: "", Error: atdid.ErrServiceNotFound},
		{Name: "other id", Services: service("#bsky_fg", atdid.ServiceTypePDS, `"https://pds.example.com"`), Error: atdid.ErrServiceNotFound},
		{Name: "wrong type", Services: service("#atproto_pds", "BskyFeedGenerator", `"https://pds.example.com"`), Error: atdid.ErrBadService},
		{Name: "map endpoint", Services: service("#atproto_pds", atdid.ServiceTypePDS, `{"origins":["https://pds.example.com"]}`), Error: atdid.ErrBadService},
		{Name: "not http", Services: service("#atproto_pds", atdid.ServiceTypePDS, `"ftp://pds.example.com"`), Error: atdid.ErrBadService},
		{Name: "upper-case scheme", Services: service("#atproto_pds", atdid.ServiceTypePDS, `"HTTPS://pds.example.com"`), Error: atdid.ErrBadService},
		{Name: "no host", Services: service("#atproto_pds", atdid.ServiceTypePDS, `"https://"`), Error: atdid.ErrBadService},
		{Name: "not a URL", Services: service("#atproto_pds", atdid.ServiceTypePDS, `"https://pds example.com"`), Error: atdid.ErrBadService},
	}

	for _, test := range tests {
		document := documentWith(t, "", test.Services)

		endpoint, err := atdid.PDSEndpoint(document)
		if nil == test.Error {
			if nil != err {
				t.Errorf("For %s, did not expect an error but actually got one: (%T) %s", test.Name, err, err)
				continue
			}
			if test.Expected != endpoint {
				t.Errorf("For %s, expected %q but actually got %q.", test.Name, test.Expected, endpoint)
			}
			continue
		}
		if !errors.Is(err, test.Error) {
			t.Errorf("For %s, expected an error wrapping %q but actually got: %v", test.Name, test.Error, err)
		}
	}
}

func TestHandle(t *testing.T) {
	tests := []struct {
		AlsoKnownAs string
		Expected    string
		Found       bool
	}{
		{AlsoKnownAs: `["at://alice.example.com"]`, Expected: "alice.example.com", Found: true},
		{AlsoKnownAs: `["https://alice.example.com","at://alice.example.com","at://bob.example.com"]`, Expected: "alice.example.com", Found: true},
		{AlsoKnownAs: `["https://alice.example.com"]`, Found: false},
		{AlsoKnownAs: `[]`, Found: false},
	}

	for _, test := range tests {
		document := mustParseDocument(t, fmt.Sprintf(`{"id":%q,"alsoKnownAs":%s}`, testDID, test.AlsoKnownAs))

		handle, found := atdid.Handle(document)
		if test.Found != found || test.Expected != handle {
			t.Errorf("For %s, expected %q (found=%t) but actually got %q (found=%t).", test.AlsoKnownAs, test.Expected, test.Found, handle, found)
		}
	}
}
