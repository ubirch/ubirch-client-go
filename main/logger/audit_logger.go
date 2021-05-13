package logger

import log "github.com/sirupsen/logrus"

const auditKeyWord = "AUDIT"

var auditLogFields = log.Fields{"tags": []string{auditKeyWord}}

func AuditLogf(format string, args ...interface{}) {
	log.WithFields(auditLogFields).Infof(format, args...)
}
