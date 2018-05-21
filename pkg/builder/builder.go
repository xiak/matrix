package builder

import (
	"github.com/xiak/matrix/pkg/ship"
)

type Builder struct {
	Name 	string
	Type 	ship.T
}

func (s *Builder)Register(name string) {
	s.Name = name
	s.Type = ship.Builder
}

