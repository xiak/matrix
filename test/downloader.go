package main

import (
	"github.com/xiak/matrix/pkg/base"
	"time"
	"fmt"
)

func main() {
	equip, err := base.NewEquipHttp("http://mp3-cdn2.luoo.net/low/luoo/radio726/01.mp3", 5*time.Second, 5*time.Second)
	if err != nil {
		fmt.Errorf("Equip http failed: %v", err)
	}
	fmt.Printf("%v", equip)
}