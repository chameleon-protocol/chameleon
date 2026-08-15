module github.com/chameleon-protocol/chameleon/tests/v2

go 1.25.0

require (
	github.com/chameleon-protocol/chameleon/core/v2 v2.0.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/google/gopacket v1.1.19 // indirect
	github.com/huin/goupnp v1.2.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/koron/go-ssdp v0.0.4 // indirect
	github.com/libp2p/go-nat v1.0.1-0.20250821073202-01afc089f138 // indirect
	github.com/libp2p/go-netroute v0.2.1 // indirect
	github.com/pion/dtls/v3 v3.1.4 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/stun/v3 v3.1.6 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/sync v0.22.0 // indirect
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/chameleon-protocol/chameleon/extras/v2 v2.0.0
	github.com/chameleon-protocol/quic-go v0.61.1-0.20260815030739-0acaf9d284cc // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	golang.org/x/crypto v0.54.0
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// The test bed is never released; it always builds against the tree it lives in.
replace github.com/chameleon-protocol/chameleon/core/v2 => ../core

replace github.com/chameleon-protocol/chameleon/extras/v2 => ../extras
