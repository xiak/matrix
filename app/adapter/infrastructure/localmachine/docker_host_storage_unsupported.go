//go:build !linux

package localmachine

import "errors"

func readDockerHostStorage(string) (uint64, uint64, error) {
	return 0, 0, errors.New("Docker host storage probing requires Linux")
}
