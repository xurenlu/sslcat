//go:build linux

package monitor

import "golang.org/x/sys/unix"

func getSystemMemory() (total uint64, free uint64, err error) {
	var info unix.Sysinfo_t
	if err = unix.Sysinfo(&info); err != nil {
		return 0, 0, err
	}
	unit := uint64(info.Unit)
	if unit == 0 {
		unit = 1
	}
	total = uint64(info.Totalram) * unit
	free = uint64(info.Freeram) * unit
	return total, free, nil
}
