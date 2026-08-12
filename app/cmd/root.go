package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	appLogo = `
░█▀▀░█░█░█▀█░█▀▄▀█░█▀▀░█░░░█▀▀░█▀█░█▄░█
░█░░░█▀█░█▀█░█░▀░█░█▀▀░█░░░█▀▀░█░█░█░▀█
░▀▀▀░▀░▀░▀░▀░▀░░░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░░▀
`
	appDesc    = "a censorship-resistant transport that keeps working when the network does not"
	appAuthors = "https://github.com/chameleon-protocol/chameleon"

	appLogLevelEnv  = "CHAMELEON_LOG_LEVEL"
	appLogFormatEnv = "CHAMELEON_LOG_FORMAT"
	appACMEDirEnv   = "CHAMELEON_ACME_DIR"
)

var (
	// These values will be injected by the build system
	appVersion   = "Unknown"
	appDate      = "Unknown"
	appType      = "Unknown" // aka channel
	appToolchain = "Unknown"
	appCommit    = "Unknown"
	appPlatform  = "Unknown"
	appArch      = "Unknown"
	libVersion   = "Unknown"

	appVersionLong = fmt.Sprintf("Version:\t%s\n"+
		"BuildDate:\t%s\n"+
		"BuildType:\t%s\n"+
		"Toolchain:\t%s\n"+
		"CommitHash:\t%s\n"+
		"Platform:\t%s\n"+
		"Architecture:\t%s\n"+
		"Libraries:\tquic-go=%s",
		appVersion, appDate, appType, appToolchain, appCommit, appPlatform, appArch, libVersion)

	appAboutLong = fmt.Sprintf("%s\n%s\n%s\n\n%s", appLogo, appDesc, appAuthors, appVersionLong)
)

var (
	logger       *zap.Logger
	defaultViper *viper.Viper
)

// Flags
var (
	cfgFile   string
	logLevel  string
	logFormat string
)

var rootCmd = &cobra.Command{
	Use:   "chameleon",
	Short: appDesc,
	Long:  appAboutLong,
	Run:   runClientCmd, // Default to client mode
}

var logLevelMap = map[string]zapcore.Level{
	"debug": zapcore.DebugLevel,
	"info":  zapcore.InfoLevel,
	"warn":  zapcore.WarnLevel,
	"error": zapcore.ErrorLevel,
}

var logFormatMap = map[string]zapcore.EncoderConfig{
	"console": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.RFC3339TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
	"json": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.EpochMillisTimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	initFlags()
	cobra.MousetrapHelpText = "" // Disable the mousetrap so Windows users can run the exe directly by double-clicking
	cobra.OnInitialize(initConfig)
	cobra.OnInitialize(initLogger) // initLogger must come after initConfig as it depends on config
}

func initFlags() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", envOrDefaultString(appLogLevelEnv, "info"), "log level")
	rootCmd.PersistentFlags().StringVarP(&logFormat, "log-format", "f", envOrDefaultString(appLogFormatEnv, "console"), "log format")
}

func initConfig() {
	defaultViper = viper.New()
	if cfgFile != "" {
		defaultViper.SetConfigFile(cfgFile)
	} else {
		defaultViper.SetConfigName("config")
		defaultViper.SetConfigType("yaml")
		viper.SupportedExts = append([]string{"yaml", "yml"}, viper.SupportedExts...)
		defaultViper.AddConfigPath(".")
		defaultViper.AddConfigPath("$HOME/.chameleon")
		defaultViper.AddConfigPath("/etc/chameleon/")
	}
}

func initLogger() {
	level, ok := logLevelMap[strings.ToLower(logLevel)]
	if !ok {
		fmt.Printf("unsupported log level: %s\n", logLevel)
		os.Exit(1)
	}
	enc, ok := logFormatMap[strings.ToLower(logFormat)]
	if !ok {
		fmt.Printf("unsupported log format: %s\n", logFormat)
		os.Exit(1)
	}
	c := zap.Config{
		Level:             zap.NewAtomicLevelAt(level),
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          strings.ToLower(logFormat),
		EncoderConfig:     enc,
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}
	var err error
	logger, err = c.Build()
	if err != nil {
		fmt.Printf("failed to initialize logger: %s\n", err)
		os.Exit(1)
	}
}

func envOrDefaultString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
