//go:build !windows

package localmachine

import "golang.org/x/sys/unix"

func availableFilesystemBytes(path string) (uint64, error) {
	var status unix.Statfs_t
	if err := unix.Statfs(path, &status); err != nil {
		return 0, err
	}
	if status.Bavail < 0 || status.Bsize < 0 {
		return 0, unix.EINVAL
	}
	available := uint64(status.Bavail)
	blockSize := uint64(status.Bsize)
	if blockSize != 0 && available > ^uint64(0)/blockSize {
		return ^uint64(0), nil
	}
	return available * blockSize, nil
}
