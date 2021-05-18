package auditlogger

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"time"
)

const (
	timeFormat    = "2021-05-12T08:58:32+00:00"
	version       = "1"
	messageFormat = "%s: %s %s Infos(%s)" // "$Service: $action $object Infos(\"userId\":\"$userId\", \"userName\":\"$userName\")"
	loggerName    = "com.ubirch.events.AuditLogger"
	auditTag      = "AUDIT"
)

var (
	service = "unknown"
)

func SetServiceName(serviceName string) {
	service = serviceName
}

func getAuditLogFields(action, object, infos string) log.Fields {
	return log.Fields{
		"@timestamp":  time.Now().UTC().Format(timeFormat),
		"@version":    version,
		"message":     fmt.Sprintf(messageFormat, service, action, object, infos),
		"logger_name": loggerName,
		"tags":        []string{auditTag},
	}
}

func AuditLog(action, object, infos string) {
	log.WithFields(getAuditLogFields(action, object, infos)).Infof("")
}
