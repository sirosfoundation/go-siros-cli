//go:build sdk

package sdk

import "errors"

// ErrStreamingNotSupported indicates the backend connection doesn't support streaming.
var ErrStreamingNotSupported = errors.New("streaming not supported over HTTP backend")
