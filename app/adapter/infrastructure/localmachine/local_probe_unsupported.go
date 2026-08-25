//go:build !windows && !linux && !darwin

package localmachine

import "errors"

func readLocalMetrics(string) (localMetrics, error) {
	return localMetrics{}, errors.New("local host probing is unsupported on this platform")
}
