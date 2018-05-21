package config

import (
    "runtime"
    "gopkg.in/ini.v1"
    log "github.com/xiak/matrix/pkg/common/logger"
    "path/filepath"
    "os"
)

const (
    PRODUCT string = "production"
    DEVELOP string = "development"
    TESTING string = "testing"
)

type Config struct {
    // PRODUCT, DEVELOP, TESTING
    Env         string

    /**
     * Build Info
     * @var Version Build version (1.0.0)
     * @var TimeStamp Build time (1523868716.4271872)
     * @var Committer Who committed code? (Dev or QA name)
     */
    Version     string
    TimeStamp   int64
    Committer   string

    /**
     * @var LogPath Log path string
     * @var ErrPath Err log path string
     */
    HomePath    string
    ConfPath    string
    LogsPath    string
    ErrsPath    string

    /**
     * @var logger Config Logger
     */
    logger      log.ILogger
    IsWindows   bool
}

func init() {
    NewConfig()
}

func NewConfig() *Config{
    // Init Logger, default is Uber zap logger
    logFactory := new(log.LoggerFactorty)
    logger := logFactory.Create(log.ZAP)

    // Set home path and config file path
    home, _ := filepath.Abs(".")
    confFile := filepath.Join(home, "conf/default.ini")
    if !FileIsExist(confFile) {
        // Try parent directory
        confFile = filepath.Join(home, "../conf/default.ini")
        if FileIsExist(confFile) {
            home = filepath.Join(home, "../")

        } else {
            logger.Fatalf("Config file is not existed. File path is %s", home)
        }
    }

    // Default log path
    logPath := filepath.Join(home, "./logs")
    errLogPath := logPath

    return &Config{
        Env: DEVELOP,
        IsWindows: runtime.GOOS == "windows",
        logger: logger,
        ConfPath: confFile,
        LogsPath: logPath,
        ErrsPath: errLogPath,
    }
}

func FileIsExist(path string) bool {
    // Get file state
    _, err := os.Stat(path)
    if err == nil {
        return true
    }
    if os.IsNotExist(err) {
        return false
    }
    return false
}

func (c *Config)ParseConfigFile(fp string) error {
    if  fp == "" {
        fp = filepath.Join(c.HomePath, c.ConfPath)
    }
    config, err := ini.Load(fp)
    if err != nil {
        c.logger.Fatalf("Failed to parse config file %v: %v", config, err)
        return err
    }

    config.BlockMode = false
    return nil
}

func (c *Config)Relocate(conf *Config) {
    c.logger.Info("Relocate configurations")
    *c = *conf
}
