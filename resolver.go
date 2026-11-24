package atdid

import (
	"context"
	"io"
	"net/http"
	"strings"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"
	"github.com/reiver/go-did"
)

// DefaultPLCDirectory is the PLC directory a [Resolver] uses unless told otherwise.
const DefaultPLCDirectory = "https://plc.directory"

// DefaultMaxDocumentSize is the largest DID document (in bytes) a [Resolver] accepts unless told otherwise.
const DefaultMaxDocumentSize = 512 * 1024

// Accept is the HTTP "Accept" header a [Resolver] sends.
const Accept = "application/did+ld+json,application/json"

// Resolver resolves did:plc and did:web DIDs to their DID documents.
//
// The zero value is ready to use. It does not cache.
type Resolver struct {
	// HTTPClient makes the HTTP requests. (Redirects are never followed — a redirect is an error.)
	// If nil, http.DefaultClient is used.
	//
	// A did:web names any host; to resolve DIDs from untrusted sources, use a client that refuses private and loopback addresses.
	HTTPClient *http.Client

	// PLCDirectory is the PLC directory's URL (ex: "https://plc.directory"). If "", DefaultPLCDirectory is used.
	PLCDirectory string

	// MaxDocumentSize is the largest DID document (in bytes) accepted. If 0 (or less), DefaultMaxDocumentSize is used.
	MaxDocumentSize int64
}

// Resolve fetches the DID document of 'id' — a did:plc or did:web (see [Validate]).
//
// A did:plc's document comes from the PLC directory ("<directory>/<did>"); a did:web's from "https://<host>/.well-known/did.json".
//
// It returns an error wrapping [ErrNotFound] if the DID positively does not exist — the PLC directory answered 404, or the did:web host answered with anything other than 2xx.
// It returns an error wrapping [ErrResolutionFailed] if it could not tell (ex: a network error, a redirect, a 5xx from the PLC directory, or a document that is too large),
// and one wrapping [ErrBadDocument] if the document is not a valid DID document for 'id' — its "id" must be 'id'.
//
// Use 'ctx' for a timeout.
func (receiver Resolver) Resolve(ctx context.Context, id string) (did.Document, error) {
	if err := Validate(id); nil != err {
		return did.Document{}, err
	}

	var isPLC bool = strings.HasPrefix(id, PrefixPLC)

	var documentURL string
	if isPLC {
		var directory string = receiver.PLCDirectory
		if "" == directory {
			directory = DefaultPLCDirectory
		}
		documentURL = strings.TrimSuffix(directory, "/") + "/" + id
	} else {
		documentURL = webDocumentURL(id)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, documentURL, nil)
	if nil != err {
		return did.Document{}, erorr.Wrap(ErrResolutionFailed, "could not make the HTTP request", field.String("did", id), field.String("url", documentURL), field.Error("error", err))
	}
	request.Header.Set("Accept", Accept)

	var client http.Client
	if nil != receiver.HTTPClient {
		client = *receiver.HTTPClient
	} else {
		client = *http.DefaultClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	response, err := client.Do(request)
	if nil != err {
		return did.Document{}, erorr.Wrap(ErrResolutionFailed, "HTTP request failed", field.String("did", id), field.String("url", documentURL), field.Error("error", err))
	}
	defer response.Body.Close()

	var status int = response.StatusCode
	switch {
	case 200 <= status && status <= 299:
	case 300 <= status && status <= 399:
		return did.Document{}, erorr.Wrap(ErrResolutionFailed, "redirected — redirects are not followed", field.String("did", id), field.String("url", documentURL), field.Int("status", status))
	case isPLC && http.StatusNotFound == status:
		return did.Document{}, erorr.Wrap(ErrNotFound, "PLC directory does not have the DID", field.String("did", id))
	case isPLC:
		return did.Document{}, erorr.Wrap(ErrResolutionFailed, "PLC directory answered with an error", field.String("did", id), field.String("url", documentURL), field.Int("status", status))
	default:
		return did.Document{}, erorr.Wrap(ErrNotFound, "did:web host does not have the DID document", field.String("did", id), field.String("url", documentURL), field.Int("status", status))
	}

	var maxSize int64 = receiver.MaxDocumentSize
	if maxSize <= 0 {
		maxSize = DefaultMaxDocumentSize
	}
	if maxSize < response.ContentLength {
		return did.Document{}, erorr.Wrap(ErrResolutionFailed, "DID document is too large", field.String("did", id), field.Int64("content-length", response.ContentLength), field.Int64("max", maxSize))
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
	if nil != err {
		return did.Document{}, erorr.Wrap(ErrResolutionFailed, "could not read the DID document", field.String("did", id), field.Error("error", err))
	}
	if maxSize < int64(len(data)) {
		return did.Document{}, erorr.Wrap(ErrResolutionFailed, "DID document is too large", field.String("did", id), field.Int64("max", maxSize))
	}

	document, err := did.ParseDocument(data)
	if nil != err {
		return did.Document{}, erorr.Wrap(ErrBadDocument, "bad DID document", field.String("did", id), field.Error("error", err))
	}
	if id != document.ID {
		return did.Document{}, erorr.Wrap(ErrBadDocument, "DID document is for a different DID", field.String("did", id), field.String("document-id", document.ID))
	}

	return document, nil
}
