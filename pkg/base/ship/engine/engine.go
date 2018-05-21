package engine

import "time"

type Engine interface {
	// 引擎编号
	SetId(id uint64)
	GetId() uint64

	// 引擎启动失败时的尝试重启次数
	SetRetryTimes(num int)
	GetRetryTimes() int

	// 引擎使用最长时间限制
	SetDialTimeout(d time.Duration)
	GetDialTimeout() time.Duration

	// 引擎失去响应最长时间，超过后引擎会停止
	SetConnTimeout(d time.Duration)
	GetConnTimeout() time.Duration

	// 引擎描述
	SetDescription(desc string)
	GetDescription() string

	// 启动, 关闭引擎
	Start() error
	Stop() error
}
