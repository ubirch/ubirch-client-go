package logger

import log "github.com/sirupsen/logrus"

const auditKeyWord = "AUDIT"

var auditLogFields = log.Fields{"tags": []string{auditKeyWord}}

func AuditLog(msg string) {
	log.WithFields(auditLogFields).Infof(msg)
}
