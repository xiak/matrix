package logger

import (
    "testing"
    "fmt"
)

func TestLoggerFactorty_Create(t *testing.T) {
    factory := new(LoggerFactorty)
    log := factory.Create(ZAP)
    log.Debug("Hello 1")
    log.Debugf("%s", "Hello 2")
    log.Info("Hello 3")
    log.Infof("%s", "Hello 4")
    log.Warn("Hello 5")
    log.Warnf("%s", "Hello 6")
    log.Error("Hello 7")
    log.Errorf("%s", "Hello 8")
}

func TestLoggerFactorty_GetLogger(t *testing.T) {
    factory := new(LoggerFactorty)
    fmt.Printf("%#v\n", factory.Create(ZAP))
    log := factory.GetLogger()
    fmt.Printf("%#v\n", log)
    log.Debug("GetLogger 1")
    log.Debugf("%s", "GetLogger 2")
    log.Info("GetLogger 3")
    log.Infof("%s", "GetLogger 4")
    log.Warn("GetLogger 5")
    log.Warnf("%s", "GetLogger 6")
    log.Error("GetLogger 7")
    log.Errorf("%s", "GetLogger 8")
    //log.Panic("GetLogger 9")
    //log.Panicf("%s", "GetLogger 10")
}