package kafka

import "openappsec.io/log"

type kafkaLogger struct {
	logLevel log.Level
	eventID  string
}

// newKafkaLogger returns a kafka logger implementation
func newKafkaLogger(logLevel log.Level, eventID string) *kafkaLogger {
	return &kafkaLogger{logLevel: logLevel, eventID: eventID}
}

// Printf implements kafka logger printer
func (k *kafkaLogger) Printf(format string, args ...interface{}) {
	switch k.logLevel {
	case log.ErrorLevel:
		log.WithEventID(k.eventID).Errorf(format, args...)
	case log.WarnLevel:
		log.WithEventID(k.eventID).Warnf(format, args...)
	case log.DebugLevel:
		log.WithEventID(k.eventID).Debugf(format, args...)
	case log.InfoLevel:
		log.WithEventID(k.eventID).Infof(format, args...)
	}
}
