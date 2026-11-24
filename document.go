package atdid

import (
	"net/url"
	"strings"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"
	"github.com/reiver/go-did"
	"github.com/reiver/go-didkey"

	"github.com/reiver/go-atdid/internal/base58"
)

// The ids (relative to the DID document) of what ATProto looks for in a DID document.
const (
	IDSigningKey = "#atproto"
	IDKEMKey     = "#atproto_kem"
	IDPDS        = "#atproto_pds"
)

// ServiceTypePDS is the "type" the [IDPDS] service must have.
const ServiceTypePDS = "AtprotoPersonalDataServer"

// The verification method "type"s ATProto keys may have.
//
// [TypeMultikey] is the usual one. The other two are legacy: their "publicKeyMultibase" is the bare public key (with no multicodec).
const (
	TypeMultikey                          = "Multikey"
	TypeEcdsaSecp256r1VerificationKey2019 = "EcdsaSecp256r1VerificationKey2019"
	TypeEcdsaSecp256k1VerificationKey2019 = "EcdsaSecp256k1VerificationKey2019"
)

// Handle returns the account's handle, as claimed by the DID document — its first "alsoKnownAs" that starts with "at://", without the "at://".
//
// The claim is only half of it: the handle must also resolve back to the DID.
func Handle(document did.Document) (string, bool) {
	for _, alias := range document.AlsoKnownAs {
		if handle, found := strings.CutPrefix(alias, "at://"); found {
			return handle, true
		}
	}
	return "", false
}

// SigningKey returns the account's signing key — the DID document's [IDSigningKey] verification method.
//
// It is P-256 or secp256k1.
func SigningKey(document did.Document) (didkey.PublicKey, error) {
	method, found := document.VerificationMethodByID(IDSigningKey)
	if !found {
		return didkey.PublicKey{}, erorr.Wrap(ErrKeyNotFound, "DID document has no signing key", field.String("did", document.ID), field.String("id", IDSigningKey))
	}

	return verificationMethodKey(method)
}

// KEMKey returns the account's KEM key — the DID document's [IDKEMKey] verification method — used to agree on the shared secret that MACs space responses.
//
// It must be P-256.
func KEMKey(document did.Document) (didkey.PublicKey, error) {
	method, found := document.VerificationMethodByID(IDKEMKey)
	if !found {
		return didkey.PublicKey{}, erorr.Wrap(ErrKeyNotFound, "DID document has no KEM key", field.String("did", document.ID), field.String("id", IDKEMKey))
	}

	if TypeEcdsaSecp256k1VerificationKey2019 == method.Type {
		return didkey.PublicKey{}, erorr.Wrap(ErrBadKey, "KEM key must be P-256", field.String("did", document.ID), field.String("type", method.Type))
	}

	key, err := verificationMethodKey(method)
	if nil != err {
		return didkey.PublicKey{}, err
	}
	if didkey.KeyTypeP256 != key.Type() {
		return didkey.PublicKey{}, erorr.Wrap(ErrBadKey, "KEM key must be P-256", field.String("did", document.ID), field.String("key-type", string(key.Type())))
	}

	return key, nil
}

// PDSEndpoint returns the URL of the account's PDS — the DID document's [IDPDS] service.
//
// The service must be of type [ServiceTypePDS], and its endpoint must be an http:// or https:// URL.
func PDSEndpoint(document did.Document) (string, error) {
	service, found := document.ServiceByID(IDPDS)
	if !found {
		return "", erorr.Wrap(ErrServiceNotFound, "DID document has no PDS service", field.String("did", document.ID), field.String("id", IDPDS))
	}

	if ServiceTypePDS != service.Type {
		return "", erorr.Wrap(ErrBadService, "PDS service has the wrong type", field.String("did", document.ID), field.String("type", service.Type))
	}

	endpoint, ok := service.EndpointURI()
	if !ok {
		return "", erorr.Wrap(ErrBadService, "PDS service endpoint is not a URL", field.String("did", document.ID))
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return "", erorr.Wrap(ErrBadService, "PDS service endpoint must be http:// or https://", field.String("did", document.ID), field.String("endpoint", endpoint))
	}
	if u, err := url.Parse(endpoint); nil != err || "" == u.Host {
		return "", erorr.Wrap(ErrBadService, "PDS service endpoint is not a valid URL", field.String("did", document.ID), field.String("endpoint", endpoint))
	}

	return endpoint, nil
}

func verificationMethodKey(method did.VerificationMethod) (didkey.PublicKey, error) {
	if "" == method.PublicKeyMultibase {
		return didkey.PublicKey{}, erorr.Wrap(ErrBadKey, "verification method has no \"publicKeyMultibase\"", field.String("id", method.ID))
	}

	var key didkey.PublicKey
	var err error
	switch method.Type {
	case TypeMultikey:
		key, err = didkey.ParseMultikey(method.PublicKeyMultibase)
	case TypeEcdsaSecp256r1VerificationKey2019:
		key, err = legacyKey(didkey.KeyTypeP256, method.PublicKeyMultibase)
	case TypeEcdsaSecp256k1VerificationKey2019:
		key, err = legacyKey(didkey.KeyTypeSecp256k1, method.PublicKeyMultibase)
	default:
		return didkey.PublicKey{}, erorr.Wrap(ErrBadKey, "unsupported verification method type", field.String("id", method.ID), field.String("type", method.Type))
	}
	if nil != err {
		return didkey.PublicKey{}, erorr.Wrap(ErrBadKey, "bad public key", field.String("id", method.ID), field.Error("error", err))
	}

	return key, nil
}

// legacyKey decodes a legacy "publicKeyMultibase" — base58btc ("z") of the bare public key, compressed (33 bytes) or uncompressed (65 bytes).
func legacyKey(keyType didkey.KeyType, multibase string) (didkey.PublicKey, error) {
	encoded, found := strings.CutPrefix(multibase, "z")
	if !found {
		return didkey.PublicKey{}, erorr.Wrap(ErrBadKey, "bad multibase — must start with \"z\" (base58btc)")
	}

	decoded, err := base58.Decode(encoded)
	if nil != err {
		return didkey.PublicKey{}, erorr.Wrap(ErrBadKey, "bad base58btc", field.Error("error", err))
	}

	switch {
	case 33 == len(decoded):
		return didkey.FromCompressed(keyType, decoded)
	case 65 == len(decoded) && 0x04 == decoded[0]:
		var compressed []byte = make([]byte, 33)
		compressed[0] = 0x02 | (decoded[64] & 0x01)
		copy(compressed[1:], decoded[1:33])

		key, err := didkey.FromCompressed(keyType, compressed)
		if nil != err {
			return didkey.PublicKey{}, err
		}
		if string(key.Uncompressed()) != string(decoded) {
			return didkey.PublicKey{}, erorr.Wrap(ErrBadKey, "not a valid point on the curve")
		}
		return key, nil
	default:
		return didkey.PublicKey{}, erorr.Wrap(ErrBadKey, "bad key length — must be 33 (compressed) or 65 (uncompressed) bytes", field.Int("length", len(decoded)))
	}
}
