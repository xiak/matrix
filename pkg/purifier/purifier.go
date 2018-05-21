package purifier

import (
	"go.uber.org/zap"
	"github.com/pkg/errors"
	"github.com/xiak/matrix/pkg/ship"
	"github.com/xiak/matrix/pkg/common/logger"
	"github.com/xiak/matrix/pkg/equipment"
	"fmt"
	"net/http"
)

const (
	ErrMissCourse = "Purifier must be set course first"
	ErrMissCollector = "Purifier must be equip collector"
)

type Purifier struct {
	Name 		string
	T	 		ship.T
	Course 		string
	Equipment  	ship.Collector
}

func DefaultPurifier(course string, v *http.Response) (*Purifier, error) {
	collector, err := equipment.DefaultHttpCollector(v)
	if err != nil {
		return nil, err
	}
	return &Purifier{
		Name: 	"Purifier - Http",
		T:		ship.Purifier,
		Course: course,
		Equipment: collector,
	}, nil
}

func (s *Purifier)SetCourse(c string) {
	s.Course = c
}

func (s *Purifier)Equip(w ship.Equipment) {
	s.Equipment = w
}

func (s *Purifier)Engage() (ship.Spoil, error) {
	if s.Course == "" {
		s.ErrMsg(ErrMissCourse)
		return nil, errors.New(ErrMissCourse)
	}
	if s.Equipment == nil {
		s.ErrMsg(ErrMissCollector)
		return nil, errors.New(ErrMissCollector)
	}

	spoil, err := s.Equipment.Collect(s.Course)
	if err != nil {
		s.ErrMsg(err.Error())
		return nil, err
	}
	return spoil, nil
}

func (s *Purifier)ErrMsg(msg string) {
	logger.Zap.Errors(msg,
		zap.String("type", fmt.Sprint(s.T)),
	)
}

