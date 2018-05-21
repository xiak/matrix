package logger

import (
    "os"
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
    "gopkg.in/natefinch/lumberjack.v2"
    "fmt"
)

type ZapLogger struct {
    *zap.Logger
}

var Zap = func() *ZapLogger {
    return NewZapLogger(&Logger{
        // Log
        Lp: "logs/log.zap.json",
        LogMaxSize: 500,        // Megabytes
        LogMaxBackups: 3,
        LogMaxAge: 28,          // Day

        // Err log
        Elp: "logs/err.zap.json",
        ErrMaxSize: 500,        // Megabytes
        ErrMaxBackups: 3,
        ErrMaxAge: 28,          // Day
    })
}()

func NewZapLogger(log *Logger) *ZapLogger {
    if len(log.Lp) == 0 || len(log.Elp) == 0 {
        panic("Log file path is null")
    }
    // First, define our level-handling logic.
    high := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
        return lvl >= zapcore.ErrorLevel
    })
    low := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
        return lvl < zapcore.ErrorLevel
    })

    // Writer
    highWriter := zapcore.AddSync(&lumberjack.Logger{
        Filename:   log.Elp,
        MaxSize:    log.ErrMaxSize, // megabytes
        MaxBackups: log.ErrMaxBackups,
        MaxAge:     log.ErrMaxAge, // days
    })
    lowWriter := zapcore.AddSync(&lumberjack.Logger{
        Filename:   log.Lp,
        MaxSize:    log.LogMaxSize, // megabytes
        MaxBackups: log.LogMaxBackups,
        MaxAge:     log.LogMaxAge, // days
    })

    // High-priority output should also go to standard error, and low-priority
    // output should also go to standard out.
    consoleDebugging := zapcore.Lock(os.Stdout)
    consoleErrors := zapcore.Lock(os.Stderr)

    // Optimize the Kafka output for machine consumption and the console output
    // for human operators.
    productEncoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
    consoleEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())

    // Join the outputs, encoders, and level-handling functions into
    // zapcore.Cores, then tee the four cores together.
    core := zapcore.NewTee(
        zapcore.NewCore(productEncoder, highWriter, high),
        zapcore.NewCore(consoleEncoder, consoleErrors, high),
        zapcore.NewCore(productEncoder, lowWriter, low),
        zapcore.NewCore(consoleEncoder, consoleDebugging, low),
    )
    logger := zap.New(core)
    defer logger.Sync()
    return &ZapLogger{
        logger,
    }
}

func (z *ZapLogger)Debug(msg string) {
    z.Logger.Debug(msg)
}

func (z *ZapLogger)Debugf(msg string, v ...interface{}) {
    z.Logger.Debug(fmt.Sprintf(msg, v ...))
}

func (z *ZapLogger)Debugs(msg string, fields ...zapcore.Field) {
    z.Logger.Debug(msg, fields...)
}

func (z *ZapLogger)Info(msg string) {
    z.Logger.Info(msg)
}

func (z *ZapLogger)Infof(msg string, v ...interface{}) {
    z.Logger.Info(fmt.Sprintf(msg, v ...))
}

func (z *ZapLogger)Infos(msg string, fields ...zapcore.Field) {
    z.Logger.Info(msg, fields...)
}

func (z *ZapLogger)Warn(msg string) {
    z.Logger.Warn(msg)
}

func (z *ZapLogger)Warnf(msg string, v ...interface{}) {
    z.Logger.Warn(fmt.Sprintf(msg, v ...))
}

func (z *ZapLogger)Warns(msg string, fields ...zapcore.Field) {
    z.Logger.Warn(msg, fields...)
}


func (z *ZapLogger)Error(msg string) {
    z.Logger.Error(msg)
}

func (z *ZapLogger)Errorf(msg string, v ...interface{}) {
    z.Logger.Error(fmt.Sprintf(msg, v ...))
}

func (z *ZapLogger)Errors(msg string, fields ...zapcore.Field) {
    z.Logger.Error(msg, fields...)
}

func (z *ZapLogger)Panic(msg string) {
    z.Logger.Panic(msg)
}

func (z *ZapLogger)Panicf(msg string, v ...interface{}) {
    z.Logger.Panic(fmt.Sprintf(msg, v ...))
}

func (z *ZapLogger)Panics(msg string, fields ...zapcore.Field) {
    z.Logger.Panic(msg, fields...)
}

func (z *ZapLogger)Fatal(msg string) {
    z.Logger.Fatal(msg)
}

func (z *ZapLogger)Fatalf(msg string, v ...interface{}) {
    z.Logger.Fatal(fmt.Sprintf(msg, v ...))
}

func (z *ZapLogger)Fatals(msg string, fields ...zapcore.Field) {
    z.Logger.Fatal(msg, fields...)
}
