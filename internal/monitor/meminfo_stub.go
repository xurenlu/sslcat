//go:build !linux

package monitor

import "errors"

func getSystemMemory() (uint64, uint64, error) {
	return 0, 0, errors.New("system memory info not available on this platform")
}
