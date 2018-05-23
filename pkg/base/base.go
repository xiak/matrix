package base

import (
	"sync/atomic"
	"github.com/xiak/matrix/pkg/ship"
)

/**
 * 基地
 * 功能：
 * @ShipFactory 建造各类船只
 * @EngineFactory 建造各类引擎
 * @DispatchTask 发布任务
 */
type Base interface {
	PublishQuest()
	ConsumeQuest()
}

/**
 * 地球基地设施
 */
type EarthBase struct {
	// 舰船编号，唯一
	ShipId		uint64
	// 引擎编号，唯一
	EngineId	uint64
}

/**
 * Mox是地球联邦最大的基地
 */
func Mox() *EarthBase {
	return &EarthBase{
		ShipId: 	1,
		EngineId: 	1,
	}
}

func (b *EarthBase) ShipFactory() {
	// 给新船编号
	b.ShipId = atomic.AddUint64(&b.ShipId, 1)


}

func (b *EarthBase) EngineFactory() {
	// 给引擎编号
	b.EngineId = atomic.AddUint64(&b.EngineId, 1)
}

func (b *EarthBase) PublishQuest(quest Quest) {
}

func (b *EarthBase) TakeQuest(quest Quest) {
}
