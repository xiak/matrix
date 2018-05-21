package common

import (
	"fmt"
	"errors"
	"github.com/xiak/matrix/pkg/common/logger"
	"regexp"
	"os"
)

// 文件名长度1～256
func ReviseFileName(fileName string, length uint8) (string, error) {
	runeName := []rune(fileName)
	runeLen  := len(runeName)
	if runeLen > int(length) {
		msg := fmt.Sprintf("The file name is too long (%d > 255)", runeLen)
		logger.Log.Errorf(msg)
		return "", errors.New(msg)
	}
	re, _ := regexp.Compile("\\\\|/|:|\\*|\\?|\"|\\<|\\>|\\|")
	fileName = re.ReplaceAllString(fileName, " ")
	return fileName, nil
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

