package main

import (
	"fmt"
	"strings"
	"regexp"
	"strconv"
)

// Id must be like 090 or 00001
func IntelligentId(id string, length uint8) string {
	re, _ := regexp.Compile("^0*")
	id = re.ReplaceAllString(id, "")
	format := "%0" + strconv.Itoa(int(length)) + "s"
	id = fmt.Sprintf(format, id)
	return id
}


func main()  {
	s := "中文字符串\n"
	fmt.Printf("长度为: %d, %d\n", strings.Count(s, "")-1, len(s))
	b := "01"
	b = IntelligentId(b, 1)
	fmt.Println(b)
	s = fmt.Sprint("a", "b")
	fmt.Println(s)
}