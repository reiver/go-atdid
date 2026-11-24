package atdid

import (
	"codeberg.org/reiver/go-erorr"
)

const (
	ErrBadDID            = erorr.Error("atdid: bad DID")
	ErrBadDocument       = erorr.Error("atdid: bad DID document")
	ErrBadKey            = erorr.Error("atdid: bad key")
	ErrBadService        = erorr.Error("atdid: bad service")
	ErrKeyNotFound       = erorr.Error("atdid: key not found")
	ErrNotFound          = erorr.Error("atdid: DID not found")
	ErrResolutionFailed  = erorr.Error("atdid: DID resolution failed")
	ErrServiceNotFound   = erorr.Error("atdid: service not found")
	ErrUnsupportedMethod = erorr.Error("atdid: unsupported DID method — ATProto allows only did:plc and did:web")
)
