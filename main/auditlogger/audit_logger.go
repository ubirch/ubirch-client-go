package auditlogger

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"time"
)

const (
	timeFormat    = time.RFC3339Nano
	version       = "1"
	messageFormat = "%s: %s %s Infos(\"userId\":\"%s\", \"userName\":\"%s\")" // "$Service: $action $object Infos(\"userId\":\"$userId\", \"userName\":\"$userName\")"
	loggerName    = "com.ubirch.events.AuditLogger"
	levelValue    = 20000
	auditTag      = "AUDIT"
)

var (
	service = "unknown"
)

func SetServiceName(serviceName string) {
	service = serviceName
}

func getAuditLogFields(action, object, userId, userName, threadName string) log.Fields {
	return log.Fields{
		"@timestamp":  time.Now().UTC().Format(timeFormat),
		"@version":    version,
		"message":     fmt.Sprintf(messageFormat, service, action, object, userId, userName),
		"logger_name": loggerName,
		"thread_name": threadName,
		"level_value": levelValue,
		"tags":        []string{auditTag},
	}
}

func AuditLog(action, object, userId, userName, threadName string) {
	log.WithFields(getAuditLogFields(action, object, userId, userName, threadName)).Infof("")
}
