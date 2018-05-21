package ship

type T string
type Course string

const (
	// 掠夺者
	// 负责掠夺资源
	Reiver T = "Reiver"
	// 净化者
	// 净化掠夺回来的资源
	Purifier T = "Purifier"
	// 建造者
	// 把掠夺回来的资源建造成可用品
	Builder T = "Builder"
)

type Spoil interface {
	GetCourse() string
	Store(w interface{})
	Take() (interface{}, error)
}

type Equipment interface {
	Weapon
	Collector
}

// 飞船接口
type Ship interface {
	SetCourse(c Course)
	Equip(w Equipment)
	Engage() (Spoil, error)
}

type Weapon interface {
	Fire(method string, target string) (Spoil, error)
}

type Collector interface {
	Collect(to string) (Spoil, error)
}

type Transformer interface {
	File(to string) (err error)
}