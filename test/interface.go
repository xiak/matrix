package main

import (
	"fmt"
)

type Test interface {
	Print()
}

type DefaultTest struct {}

func NewDefaultTest() *DefaultTest {
	return &DefaultTest{}
}

func (t *DefaultTest)Print() {}

func test(v Test) {
	fmt.Printf("%#v, %d", v, v)
}

func main() {
	d := NewDefaultTest()
	test(d)
}

