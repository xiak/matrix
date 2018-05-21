package logger

import (
)

type LOGGER_TYPE int

const (
    ZAP LOGGER_TYPE = iota
)

var Log = func() ILogger {
    factory := new(LoggerFactorty)
    return factory.Create(ZAP)
}()

type ILogger interface {
    Debug(msg string)
    Debugf(format string, v ...interface{})
    Info(msg string)
    Infof(format string, v ...interface{})
    Warn(msg string)
    Warnf(format string, v ...interface{})
    Error(msg string)
    Errorf(format string, v ...interface{})
    Panic(msg string)
    Panicf(format string, v ...interface{})
    Fatal(msg string)
    Fatalf(format string, v ...interface{})
}

type ILoggerFactorty interface {
    Create(plugin LOGGER_TYPE) ILogger
    GetLogger() ILogger
}

/**
 * Logger Implement
 */
type Logger struct {
    // Log
    Lp              string  // Log Path
    LogMaxSize      int     // Megabytes
    LogMaxBackups   int
    LogMaxAge       int     // Day

    // Err log
    Elp             string  // Err log path
    ErrMaxSize      int     // Megabytes
    ErrMaxBackups   int
    ErrMaxAge       int     // Day
}


type LoggerFactorty struct {
    Logger ILogger
}

func (l *LoggerFactorty) Create(plugin LOGGER_TYPE) ILogger {
    switch plugin {
    case ZAP:
        l.Logger = Zap
    default:
        l.Logger = Zap
    }
    return l.Logger
}


func (l *LoggerFactorty) GetLogger() ILogger {
    return l.Logger
}








