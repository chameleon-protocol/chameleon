//go:build !linux

package mimic

import (
	"errors"
	"net"

	"go.uber.org/zap"
)

func Start(cfg Config, _ Role, _ *net.UDPAddr, _ *zap.Logger) (*Instance, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	return nil, errors.New("mimic is only supported on Linux")
}
