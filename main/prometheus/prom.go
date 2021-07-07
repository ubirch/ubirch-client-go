package prometheus

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

var totalRequests = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Number of get requests.",
	},
	[]string{"path"},
)

var responseStatus = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "response_status",
		Help: "Status of HTTP response",
	},
	[]string{"status"},
)

var httpDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name: "http_response_time_seconds",
		Help: "Duration of HTTP requests.",
	},
	[]string{"path"},
)

var UpstreamResponseDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
	Name:    "upstream_response_duration",
	Help:    "Duration of HTTP responses from upstream server.",
	Buckets: prometheus.LinearBuckets(0.01, 0.01, 10),
})

var SignatureCreationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "signature_creation_duration",
	Help:    "Duration of the creation of a signed object",
	Buckets: prometheus.LinearBuckets(0.01, 0.01, 10),
})

var SignatureCreationCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "signature_creation_success",
	Help: "Number of successfully created signatures",
})

var IdentityCreationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "identity_creation_duration",
	Help:    "Duration of the identity being created, registered and stored.",
	Buckets: prometheus.LinearBuckets(0.01, 0.01, 10),
})

var IdentityCreationCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "identity_creation_success",
	Help: "Number of identities which have been successfully created and stored.",
})

func RegisterPromMetrics() {
	prometheus.Register(totalRequests)
	prometheus.Register(responseStatus)
	prometheus.Register(httpDuration)
	prometheus.Register(UpstreamResponseDuration)
	prometheus.Register(SignatureCreationDuration)
	prometheus.Register(SignatureCreationCounter)
	prometheus.Register(IdentityCreationDuration)
	prometheus.Register(IdentityCreationCounter)
}

func PromMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := NewResponseWriter(w)
		startTimer := time.Now()
		next.ServeHTTP(rw, r)

		path := chi.RouteContext(r.Context()).RoutePattern()
		statusCode := rw.statusCode

		httpDuration.WithLabelValues(path).Observe(time.Since(startTimer).Seconds())
		totalRequests.WithLabelValues(path).Inc()
		responseStatus.WithLabelValues(strconv.Itoa(statusCode)).Inc()

	})
}

func InitPromMetrics(router *chi.Mux) {
	RegisterPromMetrics()
	router.Use(PromMiddleware)
	router.Method(http.MethodGet, "/metrics", promhttp.Handler())
}
