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
	ErrMissCourse = "Purifier must be set course first"
	ErrMissCollector = "Purifier must be equip collector"
)

type Builder struct {
	Name 		string
	T	 		ship.T
	Course 		string
	Equipment  	ship.Transformer
}

func DefaultBuilder(course string, v []byte) (*Builder, error) {
	trans, err := equipment.DefaultHttpTransformer(v)
	if err != nil {
		return nil, err
	}
	return &Builder{
		Name: 	"Builder - Http",
		T:		ship.Builder,
		Course: course,
		Equipment: trans,
	}, nil
}

func (s *Builder)SetCourse(c string) {
	s.Course = c
}

func (s *Builder)Equip(w ship.Equipment) {
	s.Equipment = w
}

func (s *Builder)Engage() (ship.Spoil, error) {
	if s.Course == "" {
		s.ErrMsg(ErrMissCourse)
		return nil, errors.New(ErrMissCourse)
	}
	if s.Equipment == nil {
		s.ErrMsg(ErrMissCollector)
		return nil, errors.New(ErrMissCollector)
	}

	err := s.Equipment.File(s.Course)
	if err != nil {
		s.ErrMsg(err.Error())
		return nil, err
	}
	return nil, nil
}

func (s *Builder)ErrMsg(msg string) {
	logger.Zap.Errors(msg,
		zap.String("type", fmt.Sprint(s.T)),
	)
}

