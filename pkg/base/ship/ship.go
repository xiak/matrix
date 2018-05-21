package ship

import (
	"net/url"
)

/**
 * 船
 */
type Ship interface {
	// Ship Id
	SetId(id uint64)
	GetId() uint64
	// Ship Classification Symbols
	SetClass(m string)
	GetClass() string
	// Ship formation
	SetFormation(fm string)
	GetFormation() string
	// Description of a base
	SetDescription(desc string)
	GetDescription() string
	// Set course
	SetCourse(course string)
	GetCourse() string
	// Add a engine to a base
	SetEngine(e Engine)
	GetEngine() Engine
	// 启动飞船
	Start() error
	// 停止飞船
	Stop() error
}



