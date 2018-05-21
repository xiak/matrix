package quest

import (
	"github.com/xiak/matrix/pkg/base/ship"
)

type QState int
const (
	// 准备发布
	PREPARE QState = iota
	// 发布任务，但是没有完成
	PUBLISHED
	// 执行成功
	COMPLETE
	// 执行失败
	FAILED
)

type Quest interface {
	SetTitle(title string)
	GetTitle() string
	SetDescription(desc string)
	GetDescription() string
	// 发布任务, 自动生成任务编号
	Publish()
	// 领取任务

	// 获取任务列表

	// 派遣任务

	State() QState
}

type MiningQuest struct {
	title 		string
	desc		string
	shipNum 	uint64
	ship    	ship.Miner
	state		QState
}

func DefaultMiningQuest(title string, desc string, shipNum uint64, ship ship.Miner) *MiningQuest {
	return &MiningQuest{
		title:		title,
		desc: 		desc,
		shipNum: 	shipNum,
		ship: 		ship,
		state:  	PREPARE,
	}
}

func (q *MiningQuest) Publish() {

}

