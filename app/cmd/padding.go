// chameleon -- a censorship-resistant transport
// Copyright (C) 2026 The chameleon authors
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 3 as published by the Free
// Software Foundation.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

package cmd

import (
	"github.com/chameleon-protocol/chameleon/extras/v2/crypto"
)

// paddingSeedLen is the key length handed to the core padding scheme. 32 bytes
// is what the scheme's PRF wants; it is not a protocol constant on the wire,
// since the seed never leaves the process.
const paddingSeedLen = 32

// paddingSeed derives the padding seed from the obfuscation password.
//
// The core packages cannot reach the obfuscation password: it belongs to
// extras, and core must not import extras. So the derivation happens here, at
// the one layer that can see both, and core receives only the finished key.
//
// Deriving from the obfuscation password rather than adding a config field of
// its own means padding stops being identical across deployments without
// anyone having to know that it was a problem. It costs nothing extra either:
// StretchPassword caches, and the obfuscator has already paid for this
// password by the time we get here.
func paddingSeed(password, realm string) ([]byte, error) {
	root, err := crypto.StretchPassword([]byte(password), realm)
	if err != nil {
		return nil, err
	}
	return crypto.DeriveSubkey(root, crypto.CtxAppPadding, paddingSeedLen)
}
