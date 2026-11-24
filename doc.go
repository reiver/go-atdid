/*
Package atdid implements ATProto's use of DIDs — which DIDs ATProto allows, what it reads from DID documents, and resolving DIDs to DID documents — for the Go programming language.

# DIDs

ATProto allows two DID methods:

  - did:plc — "did:plc:" then 24 characters of [a-z2-7] (ex: "did:plc:ewvi7nxzyoun6zhxrhs64oiz").
  - did:web — a hostname only (ex: "did:web:example.com"); no paths, and a port only for localhost (ex: "did:web:localhost%3A2583").

[Validate] checks a DID by these rules. [IsValid] checks only ATProto's general DID syntax (any DID method).

# DID documents

From a DID document (see github.com/reiver/go-did), ATProto reads:

	┌───────────────┬───────────────────────────┬─────────────────────────────────────────────────────┐
	│ function      │ from                      │ what                                                │
	├───────────────┼───────────────────────────┼─────────────────────────────────────────────────────┤
	│ [SigningKey]  │ "#atproto" key            │ the account's signing key (P-256 or secp256k1)      │
	│ [KEMKey]      │ "#atproto_kem" key        │ the key spaces use to agree on a MAC secret (P-256) │
	│ [PDSEndpoint] │ "#atproto_pds" service    │ the URL of the account's PDS                        │
	│ [Handle]      │ first "at://" alsoKnownAs │ the account's handle (claimed — check it too)       │
	└───────────────┴───────────────────────────┴─────────────────────────────────────────────────────┘

Keys are returned as github.com/reiver/go-didkey public keys.

# Resolving

A [Resolver] fetches a DID's document — a did:plc's from the PLC directory, a did:web's from "https://<host>/.well-known/did.json".
It does not follow redirects, limits the document's size, and checks that the document is for the DID asked for.
It does not cache.

# Example

	var resolver atdid.Resolver

	document, err := resolver.Resolve(ctx, "did:plc:ewvi7nxzyoun6zhxrhs64oiz")
	if nil != err {
		return err
	}

	key, err := atdid.SigningKey(document)
	if nil != err {
		return err
	}

	pds, err := atdid.PDSEndpoint(document)
	if nil != err {
		return err
	}
*/
package atdid
