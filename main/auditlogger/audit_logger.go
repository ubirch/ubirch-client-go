package auditlogger

import (
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	timeFormat    = time.RFC3339
	version       = "1"
	messageFormat = "%s: %s %s Infos(%s)" // "$Service: $action $object Infos(\"hwDeviceId\":\"$hwDeviceId\", \"hash\":\"$hash\")"
	loggerName    = "com.ubirch.events.AuditLogger"
	auditTag      = "AUDIT"
)

var (
	service = "unknown"
)

func SetServiceName(serviceName string) {
	service = serviceName
}

func getAuditLogFields() log.Fields {
	return log.Fields{
		"@timestamp":  time.Now().UTC().Format(timeFormat),
		"@version":    version,
		"logger_name": loggerName,
		"tags":        []string{auditTag},
	}
}

func AuditLog(action, object, infos string) {
	log.WithFields(getAuditLogFields()).Infof(messageFormat, service, action, object, infos)
}
