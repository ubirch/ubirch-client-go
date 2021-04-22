package httphelper

import (
	"fmt"
	"net/http"
)

func EmptyOk(w http.ResponseWriter) error {
	w.Header().Set(HeaderContentType, MimeTextPlain)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "")
	return nil
}