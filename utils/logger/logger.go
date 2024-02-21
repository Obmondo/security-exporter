package logger

import (
	"errors"
	"log"
	"syscall"

	"go.uber.org/zap"
)

var logging *loggerStruct

type Logger interface {
	Info(msg string, params ...any)
	Error(msg string, params ...any)
	Fatal(msg string, params ...any)
}

type loggerStruct struct {
	zapLogger *zap.SugaredLogger
}

func (logger *loggerStruct) Info(msg string, params ...any) {
	logger.zapLogger.Infow(msg, params...)
}

func (logger *loggerStruct) Error(msg string, params ...any) {
	logger.zapLogger.Errorw(msg, params...)
}

func (logger *loggerStruct) Fatal(msg string, params ...any) {
	logger.zapLogger.Fatalw(msg, params...)
}

func GetLogger() Logger {
	if logging != nil {
		return logging
	}
	zaplogger, err := zap.NewProduction(zap.AddCallerSkip(1))
	if err != nil {
		log.Println(err)
	}
	defer func(zaplogger *zap.Logger) {
		err := zaplogger.Sync()
		if !errors.Is(err, syscall.EINVAL) {
			log.Fatal(err)
		}
	}(zaplogger)

	logging = &loggerStruct{zapLogger: zaplogger.Sugar()}
	return logging
}
