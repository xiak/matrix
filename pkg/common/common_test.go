package common

import (
	"testing"
)

func TestCommon(t *testing.T) {
	ReviseFileName("中文字符长度*\\/:*?\"<>|", 255)
}