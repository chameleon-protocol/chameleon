package protocol

import (
	"net/http"
	"strconv"
)

const (
	URLHost = "chameleon"
	URLPath = "/auth"

	RequestHeaderAuth        = "Cham-Auth"
	ResponseHeaderUDPEnabled = "Cham-UDP"
	CommonHeaderCCRX         = "Cham-CC-RX"
	CommonHeaderPadding      = "Cham-Padding"

	// StatusAuthOK is a plain 200. Upstream used 233, which is a giveaway to a
	// censor who buys a subscription and probes the server with credentials that
	// work: no real web server answers 233. A 200 is indistinguishable from what
	// the masquerade handler returns, but for that same reason the status code
	// alone no longer proves the peer is one of ours — callers MUST also check
	// IsAuthResponse.
	//
	// Renaming the headers only moves the target: they are still fixed strings a
	// paying censor can grep for. Deriving them from the PSK is the actual fix.
	StatusAuthOK = http.StatusOK
)

// IsAuthResponse reports whether a 200 came from us rather than from the
// masquerade handler (or, when masq proxies upstream, from a real web server).
func IsAuthResponse(h http.Header) bool {
	return h.Get(ResponseHeaderUDPEnabled) != ""
}

// AuthRequest is what client sends to server for authentication.
type AuthRequest struct {
	Auth string
	Rx   uint64 // 0 = unknown, client asks server to use bandwidth detection
}

// AuthResponse is what server sends to client when authentication is passed.
type AuthResponse struct {
	UDPEnabled bool
	Rx         uint64 // 0 = unlimited
	RxAuto     bool   // true = server asks client to use bandwidth detection
}

func AuthRequestFromHeader(h http.Header) AuthRequest {
	rx, _ := strconv.ParseUint(h.Get(CommonHeaderCCRX), 10, 64)
	return AuthRequest{
		Auth: h.Get(RequestHeaderAuth),
		Rx:   rx,
	}
}

func AuthRequestToHeader(h http.Header, req AuthRequest, ps *PaddingScheme) {
	h.Set(RequestHeaderAuth, req.Auth)
	h.Set(CommonHeaderCCRX, strconv.FormatUint(req.Rx, 10))
	h.Set(CommonHeaderPadding, ps.orDefault().AuthRequest.generate())
}

func AuthResponseFromHeader(h http.Header) AuthResponse {
	resp := AuthResponse{}
	resp.UDPEnabled, _ = strconv.ParseBool(h.Get(ResponseHeaderUDPEnabled))
	rxStr := h.Get(CommonHeaderCCRX)
	if rxStr == "auto" {
		// Special case for server requesting client to use bandwidth detection
		resp.RxAuto = true
	} else {
		resp.Rx, _ = strconv.ParseUint(rxStr, 10, 64)
	}
	return resp
}

func AuthResponseToHeader(h http.Header, resp AuthResponse, ps *PaddingScheme) {
	h.Set(ResponseHeaderUDPEnabled, strconv.FormatBool(resp.UDPEnabled))
	if resp.RxAuto {
		h.Set(CommonHeaderCCRX, "auto")
	} else {
		h.Set(CommonHeaderCCRX, strconv.FormatUint(resp.Rx, 10))
	}
	h.Set(CommonHeaderPadding, ps.orDefault().AuthResponse.generate())
}
