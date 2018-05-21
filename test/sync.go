package main

import (
	"sync"
	"fmt"
	"runtime"
)

// sync.Pool没有控制缓存对象的数量
// 使用期限是两次GC之间
func main() {
	p := sync.Pool{
		New: func() interface{} {
			return 0
		},
	}
	 a := p.Get().(int)
	 fmt.Println(a)
	 p.Put(1)
	 p.Put(2)
	 a = p.Get().(int)
	 fmt.Println(a)
	a = p.Get().(int)
	fmt.Println(a)
	a = p.Get().(int)
	fmt.Println(a)
	p.Put(3)
	runtime.GC()
	a = p.Get().(int)
	fmt.Println(a)
}
