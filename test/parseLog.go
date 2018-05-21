package main

import (
	"os"
	"fmt"
	"bufio"
	"io"
	"time"
	"unsafe"
	"regexp"
)

type MsgQueue struct {
	Msg		string
}

func BytesToString(v []byte) string {
	return *(*string)(unsafe.Pointer(&v))
}

type ParseLine func(line []byte) *MsgQueue

func ReadLine(fp string, fn ParseLine) {
	f, err := os.Open(fp)
	defer f.Close()
	if err != nil {
		fmt.Errorf("Err: %s", err)
	}
	reader := bufio.NewReader(f)
	//queue := make([]*MsgQueue, 0)
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		fn(line)

	}
}

func main() {
	startTime := time.Now().UnixNano()
	ReadLine("logs/ERROR.txt", func(line []byte) *MsgQueue {
		re, _ := regexp.Compile(`.+http://.+radio(.+)/(.+)\.mp3"}`)
		m := re.Match(line)
		if m {
			str := re.ReplaceAllString(BytesToString(line), "$1 $2")
			fmt.Printf("Line: %s\n", str)
			return &MsgQueue{Msg: ""}
		}

	})
	endTime := time.Now().UnixNano()
	fmt.Printf("Time Duration: %dms, %dns", (endTime-startTime)/1e6, (endTime-startTime))
}
