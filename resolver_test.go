package atdid_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/reiver/go-atdid"
)

// fakeTransport answers every request with a canned response, and remembers the request.
type fakeTransport struct {
	Status   int
	Header   http.Header
	Body     string
	Err      error
	Requests []*http.Request
}

func (receiver *fakeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	receiver.Requests = append(receiver.Requests, request)
	if err := request.Context().Err(); nil != err {
		return nil, err
	}
	if nil != receiver.Err {
		return nil, receiver.Err
	}

	var header http.Header = receiver.Header
	if nil == header {
		header = http.Header{}
	}
	var contentLength int64 = -1
	if value := header.Get("Content-Length"); "" != value {
		contentLength, _ = strconv.ParseInt(value, 10, 64)
	}
	return &http.Response{
		StatusCode:    receiver.Status,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(receiver.Body)),
		ContentLength: contentLength,
		Request:       request,
	}, nil
}

func minimalDocument(id string) string {
	return fmt.Sprintf(`{"id":%q,"alsoKnownAs":["at://alice.example.com"]}`, id)
}

func TestResolver_Resolve(t *testing.T) {
	tests := []struct {
		Name        string
		Resolver    atdid.Resolver
		DID         string
		ExpectedURL string
	}{
		{Name: "did:plc default directory", DID: testDID, ExpectedURL: "https://plc.directory/" + testDID},
		{Name: "did:plc other directory", Resolver: atdid.Resolver{PLCDirectory: "https://plc.example.com/"}, DID: testDID, ExpectedURL: "https://plc.example.com/" + testDID},
		{Name: "did:web", DID: "did:web:example.com", ExpectedURL: "https://example.com/.well-known/did.json"},
		{Name: "did:web localhost", DID: "did:web:localhost", ExpectedURL: "http://localhost/.well-known/did.json"},
		{Name: "did:web localhost port", DID: "did:web:localhost%3A2583", ExpectedURL: "http://localhost:2583/.well-known/did.json"},
	}

	for _, test := range tests {
		transport := &fakeTransport{Status: http.StatusOK, Body: minimalDocument(test.DID)}
		var resolver atdid.Resolver = test.Resolver
		resolver.HTTPClient = &http.Client{Transport: transport}

		document, err := resolver.Resolve(context.Background(), test.DID)
		if nil != err {
			t.Errorf("For %s, did not expect an error but actually got one: (%T) %s", test.Name, err, err)
			continue
		}
		if test.DID != document.ID {
			t.Errorf("For %s, expected the document for %q but actually got one for %q.", test.Name, test.DID, document.ID)
		}

		if 1 != len(transport.Requests) {
			t.Errorf("For %s, expected 1 request but actually got %d.", test.Name, len(transport.Requests))
			continue
		}
		var request *http.Request = transport.Requests[0]
		if actual := request.URL.String(); test.ExpectedURL != actual {
			t.Errorf("For %s, expected the URL %q but actually got %q.", test.Name, test.ExpectedURL, actual)
		}
		if http.MethodGet != request.Method {
			t.Errorf("For %s, expected the method %q but actually got %q.", test.Name, http.MethodGet, request.Method)
		}
		if actual := request.Header.Get("Accept"); atdid.Accept != actual {
			t.Errorf("For %s, expected the Accept header %q but actually got %q.", test.Name, atdid.Accept, actual)
		}
	}
}

func TestResolver_Resolve_errors(t *testing.T) {
	const webDID = "did:web:example.com"

	tests := []struct {
		Name      string
		DID       string
		Transport fakeTransport
		MaxSize   int64
		Expected  error
		Requests  int
	}{
		{Name: "bad DID", DID: "did:plc:short", Expected: atdid.ErrBadDID},
		{Name: "unsupported method", DID: "did:key:" + secp256k1Multikey, Expected: atdid.ErrUnsupportedMethod},

		{Name: "plc 404", DID: testDID, Transport: fakeTransport{Status: http.StatusNotFound}, Expected: atdid.ErrNotFound, Requests: 1},
		{Name: "plc 410", DID: testDID, Transport: fakeTransport{Status: http.StatusGone}, Expected: atdid.ErrResolutionFailed, Requests: 1},
		{Name: "plc 500", DID: testDID, Transport: fakeTransport{Status: http.StatusInternalServerError}, Expected: atdid.ErrResolutionFailed, Requests: 1},
		{Name: "web 404", DID: webDID, Transport: fakeTransport{Status: http.StatusNotFound}, Expected: atdid.ErrNotFound, Requests: 1},
		{Name: "web 500", DID: webDID, Transport: fakeTransport{Status: http.StatusInternalServerError}, Expected: atdid.ErrNotFound, Requests: 1},

		{Name: "plc redirect", DID: testDID, Transport: fakeTransport{Status: http.StatusFound, Header: http.Header{"Location": {"https://elsewhere.example.com/"}}}, Expected: atdid.ErrResolutionFailed, Requests: 1},
		{Name: "web redirect", DID: webDID, Transport: fakeTransport{Status: http.StatusMovedPermanently, Header: http.Header{"Location": {"https://elsewhere.example.com/did.json"}}}, Expected: atdid.ErrResolutionFailed, Requests: 1},
		{Name: "network error", DID: testDID, Transport: fakeTransport{Err: errors.New("connection refused")}, Expected: atdid.ErrResolutionFailed, Requests: 1},

		{Name: "too large", DID: testDID, Transport: fakeTransport{Status: http.StatusOK, Body: minimalDocument(testDID)}, MaxSize: int64(len(minimalDocument(testDID)) - 1), Expected: atdid.ErrResolutionFailed, Requests: 1},
		{Name: "too large, by header", DID: testDID, Transport: fakeTransport{Status: http.StatusOK, Header: http.Header{"Content-Length": {"999999999"}}, Body: minimalDocument(testDID)}, Expected: atdid.ErrResolutionFailed, Requests: 1},

		{Name: "not JSON", DID: testDID, Transport: fakeTransport{Status: http.StatusOK, Body: "<html></html>"}, Expected: atdid.ErrBadDocument, Requests: 1},
		{Name: "other DID", DID: testDID, Transport: fakeTransport{Status: http.StatusOK, Body: minimalDocument("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")}, Expected: atdid.ErrBadDocument, Requests: 1},
		{Name: "other did:web", DID: webDID, Transport: fakeTransport{Status: http.StatusOK, Body: minimalDocument("did:web:example.org")}, Expected: atdid.ErrBadDocument, Requests: 1},
	}

	for _, test := range tests {
		var transport *fakeTransport = &test.Transport
		var resolver atdid.Resolver = atdid.Resolver{
			HTTPClient:      &http.Client{Transport: transport},
			MaxDocumentSize: test.MaxSize,
		}

		_, err := resolver.Resolve(context.Background(), test.DID)
		if !errors.Is(err, test.Expected) {
			t.Errorf("For %s, expected an error wrapping %q but actually got: %v", test.Name, test.Expected, err)
		}
		if test.Requests != len(transport.Requests) {
			t.Errorf("For %s, expected %d request(s) but actually got %d.", test.Name, test.Requests, len(transport.Requests))
		}
	}
}

func TestResolver_Resolve_maxSize(t *testing.T) {
	var body string = minimalDocument(testDID)
	transport := &fakeTransport{Status: http.StatusOK, Body: body}
	var resolver atdid.Resolver = atdid.Resolver{
		HTTPClient:      &http.Client{Transport: transport},
		MaxDocumentSize: int64(len(body)),
	}

	if _, err := resolver.Resolve(context.Background(), testDID); nil != err {
		t.Errorf("Did not expect an error for a document of exactly the maximum size, but actually got one: (%T) %s", err, err)
	}
}

func TestResolver_Resolve_doesNotChangeClient(t *testing.T) {
	transport := &fakeTransport{Status: http.StatusFound, Header: http.Header{"Location": {"https://elsewhere.example.com/"}}}
	var client *http.Client = &http.Client{Transport: transport}
	var resolver atdid.Resolver = atdid.Resolver{HTTPClient: client}

	if _, err := resolver.Resolve(context.Background(), testDID); !errors.Is(err, atdid.ErrResolutionFailed) {
		t.Errorf("Expected an error wrapping %q but actually got: %v", atdid.ErrResolutionFailed, err)
	}
	if nil != client.CheckRedirect {
		t.Errorf("Expected the caller's client to be left unchanged, but its CheckRedirect was set.")
	}
}

func TestResolver_Resolve_context(t *testing.T) {
	transport := &fakeTransport{Status: http.StatusOK, Body: minimalDocument(testDID)}
	var resolver atdid.Resolver = atdid.Resolver{HTTPClient: &http.Client{Transport: transport}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := resolver.Resolve(ctx, testDID); !errors.Is(err, atdid.ErrResolutionFailed) {
		t.Errorf("Expected an error wrapping %q but actually got: %v", atdid.ErrResolutionFailed, err)
	}
}
