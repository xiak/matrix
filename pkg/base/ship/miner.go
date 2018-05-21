package ship

import (
	"sync/atomic"
	"github.com/xiak/matrix/pkg/base/ship/engine"
)

/**
 * 采矿船
 * 具备从资源星球获取资源，并运送回基地的功能
 * 例如： HTTP DOWNLOADER
 */

type Miner interface {
}

/**
 * Http Downloader
 * 默认的采矿船信息：
 * 描述： Neb级飞船，体积庞大， 没有武器装备
 * 其为Matrix主力矿船
 */
type NebShip struct {
	id			uint64
	name 		string
	class 		string
	formation	string
	course      string
	progress 	uint8
	desc        string
	engine      Engine
}

func NewNebShip(course string) *NebShip {

	return &NebShip{
		course:     course,
		engine:     nil,
		class: 		"Neb",
		formation: 	"Neb",
		progress: 	0,
	}
}

func (ship *NebShip)SetId(id uint64) {
	atomic.AddUint64(&ship.id, 1)
}

func (ship *NebShip)GetId() uint64 {
	return ship.id
}

// Ship Classification Symbols
func (ship *NebShip)SetClass(m string) {
	ship.class = m
}

func (ship *NebShip)GetClass() string {
	return ship.class
}

// Ship formation
func (ship *NebShip)SetFormation(fm string) {
	ship.formation = fm
}

func (ship *NebShip)GetFormation() string {
	return ship.formation
}

func (ship *NebShip)SetDescription(desc string) {
	ship.desc = desc
}

func (ship *NebShip)GetDescription() string {
	return ship.desc
}

func (ship *NebShip)SetCourse(course string) {
	ship.course = course
}

func (ship *NebShip)GetCourse() string {
	return ship.course
}

// 飞船执行运输任务
func (ship *NebShip)Start() (err error) {
	DefaultHttpEngine
	//// 1. check the course
	//if ship.course == nil {
	//	return nil, errors.New("Set course failed: please set course firstly before starting")
	//}
	//// 2. Check the engine
	//if ship.engine == nil {
	//	return nil, errors.New("Set engine failed: please set engine firstly before starting")
	//}
	//contactor, err := ship.engine.GetContactor()
	//if err != nil {
	//	return nil, err
	//}
	//switch engine := contactor.(type) {
	//// Client engine
	//case *http.Client:
	//	engine
	//default:
	//	return nil, errors.New("The equipped engine has not supported for base [Nebs]")
	//}
	ship.engine.Re


	return
}

func (ship *NebShip)Stop() (err error) {}