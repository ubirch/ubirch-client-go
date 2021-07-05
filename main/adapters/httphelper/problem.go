package httphelper

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// HttpProblem is an implementation of https://tools.ietf.org/html/rfc7807.
// It should be used to define once in your program the problems in use.
// HttpProblemInstances should then be used to create individual instances
// of the problems.
type HttpProblem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status,omitempty"`
}

// HttpProblemInstance implements individual instances of defined-once
// HttpProblems.
type HttpProblemInstance struct {
	HttpProblem
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	// We are not supporting extension members at the moment
	// (https://tools.ietf.org/html/rfc7807#section-3.2)
}

// Respond400 sends a HTTP status 400 response to the provided
// HTTP response writer using application/problem+json media type
// and constructs the details property from the supplied error
func Respond400(w http.ResponseWriter, detail string) {

	pi := HttpProblemInstance{
		HttpProblem: HttpProblem{
			"about:blank",
			"Bad Request",
			http.StatusBadRequest,
		},
		Detail: detail,
	}
	RespondProblem(w, pi)
}

// Respond406 sends a HTTP status 406 response to the provided
// HTTP response writer using application/problem+json media type
// and constructs the details property from the supplied problem
func Respond406(w http.ResponseWriter, detail string) {

	pi := HttpProblemInstance{
		HttpProblem: HttpProblem{
			"about:blank",
			"Not Acceptable",
			http.StatusNotAcceptable,
		},
		Detail: detail,
	}
	RespondProblem(w, pi)
}

// Respond409 sends a HTTP status 409 response to the provided
// HTTP response writer using application/problem+json media type
// and constructs the details property from the supplied conflict
func Respond409(w http.ResponseWriter, detail string) {

	pi := HttpProblemInstance{
		HttpProblem: HttpProblem{
			"about:blank",
			"Conflict",
			http.StatusConflict,
		},
		Detail: detail,
	}
	RespondProblem(w, pi)
}

// RespondProblem sends an application/problem+json response to
// the HTTP writer. The response is based on the provided
// problem instance
func RespondProblem(w http.ResponseWriter, pi HttpProblemInstance) {
	w.Header().Set(HeaderContentType, MimeApplicationProblem)
	w.WriteHeader(pi.Status)
	enc := json.NewEncoder(w)
	if err := enc.Encode(&pi); nil != err {
		// At least send the error in plain text when
		// serialization fails.
		fmt.Fprintf(w, "Error: %v (%v)", err, pi)
	}
}
