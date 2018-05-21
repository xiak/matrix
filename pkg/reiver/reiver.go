package purifier

import (
	"go.uber.org/zap"
	"github.com/pkg/errors"
	"github.com/xiak/matrix/pkg/ship"
	"github.com/xiak/matrix/pkg/common/logger"
	"github.com/xiak/matrix/pkg/equipment"
	"fmt"
)

const (
	ErrMissCourse string = "Purifier must be set course first"
	ErrMissWeapon string = "Purifier must be equip weapon"
)

type Reiver struct {
	Name 		string
	T	 		ship.T
	Course		string
	Equipment  	ship.Weapon
}

func DefaultReiver(course string) *Reiver {
	e := equipment.DefaultHttpWeapon(1, "Equip http weapon")

	return &Reiver{
		Name: 	"Reiver - Http",
		T:		ship.Purifier,
		Course: course,
		Equipment: e,
	}
}

func (s *Reiver)SetCourse(c string) {
	s.Course = c
}

func (s *Reiver)Equip(w ship.Equipment) {
	s.Equipment = w
}

func (s *Reiver)Engage() (ship.Spoil, error) {
	if s.Course == "" {
		s.ErrMsg(ErrMissCourse)
		return nil, errors.New(ErrMissCourse)
	}
	if s.Equipment == nil {
		s.ErrMsg(ErrMissWeapon)
		return nil, errors.New(ErrMissWeapon)
	}

	spoil, err := s.Equipment.Fire("GET", s.Course)
	if err != nil {
		s.ErrMsg(err.Error())
		return nil, err
	}
	return spoil, nil
}

func (s *Reiver)ErrMsg(msg string) {
	logger.Zap.Errors(msg,
		zap.String("type", fmt.Sprint(s.T)),
	)
}

