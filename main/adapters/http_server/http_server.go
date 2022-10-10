package http_server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/ubirch/ubirch-client-go/main/config"

	log "github.com/sirupsen/logrus"
	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
)

const (
	ShutdownTimeout = 10 * time.Second // time after which the server will be shut down forcefully if graceful shutdown did not happen before
	ReadTimeout     = 1 * time.Second  // maximum duration for reading the entire request -> low since we only expect requests with small content
	WriteTimeout    = 60 * time.Second // time after which the connection will be closed if response was not written -> this should never happen
	IdleTimeout     = 60 * time.Second // time to wait for the next request when keep-alives are enabled
)

type HTTPServer struct {
	Router   *chi.Mux
	Addr     string
	TLS      bool
	CertFile string
	KeyFile  string
}

func NewRouter(gatewayTimeout time.Duration) *chi.Mux {
	router := chi.NewMux()
	router.Use(prom.PromMiddleware)
	router.Use(middleware.Timeout(gatewayTimeout))
	return router
}

func InitHTTPServer(conf *config.Config,
	initialize InitializeIdentity, getCSR GetCSR,
	checkAuth CheckAuth, sign Sign,
	verify Verify, verifyOffline VerifyOffline,
	deactivate UpdateActivateStatus, reactivate UpdateActivateStatus,
	serverID string, readinessChecks []func() error) *HTTPServer {

	httpServer := &HTTPServer{
		Router:   NewRouter(time.Duration(conf.GatewayTimeoutMs) * time.Millisecond),
		Addr:     conf.TCP_addr,
		TLS:      conf.TLS,
		CertFile: conf.TLS_CertFile,
		KeyFile:  conf.TLS_KeyFile,
	}

	if conf.CORS && config.IsDevelopment { // never enable CORS on production stage
		httpServer.SetUpCORS(conf.CORS_Origins, conf.Debug)
	}

	// set up endpoints for liveness and readiness checks
	httpServer.Router.Get(LivenessCheckEndpoint, Health(serverID))
	httpServer.Router.Get(ReadinessCheckEndpoint, Ready(serverID, readinessChecks))

	// set up metrics
	httpServer.Router.Method(http.MethodGet, MetricsEndpoint, prom.Handler())

	// set up endpoint for identity registration
	if conf.EnableRegistrationEndpoint {
		httpServer.Router.Put(RegisterEndpoint, Register(conf.StaticAuth, initialize))
	}

	// set up endpoint for CSR creation
	if conf.EnableCSRCreationEndpoint {
		fetchCSREndpoint := path.Join(UUIDPath, CSREndpoint) // /<uuid>/csr
		httpServer.Router.Get(fetchCSREndpoint, FetchCSR(conf.StaticAuth, getCSR))
	}

	// set up endpoint for key status updates (de-/re-activation)
	if conf.EnableDeactivationEndpoint {
		httpServer.Router.Put(ActiveUpdateEndpoint, UpdateActive(conf.StaticAuth, deactivate, reactivate))
	}

	// set up endpoints for signing
	signingService := &SigningService{
		CheckAuth: checkAuth,
		Sign:      sign,
	}

	// chain:              /<uuid>
	// chain hash:         /<uuid>/hash
	// chain offline:      /<uuid>/offline
	// chain offline hash: /<uuid>/offline/hash
	httpServer.AddServiceEndpoint(UUIDPath,
		signingService.HandleRequest(ChainHash),
		true,
	)

	// sign:              /<uuid>/anchor
	// sign hash:         /<uuid>/anchor/hash
	// sign offline:      /<uuid>/anchor/offline
	// sign offline hash: /<uuid>/anchor/offline/hash
	httpServer.AddServiceEndpoint(path.Join(UUIDPath, string(AnchorHash)),
		signingService.HandleRequest(AnchorHash),
		true,
	)

	// disable:      /<uuid>/disable
	// disable hash: /<uuid>/disable/hash
	httpServer.AddServiceEndpoint(path.Join(UUIDPath, string(DisableHash)),
		signingService.HandleRequest(DisableHash),
		false,
	)

	// enable:      /<uuid>/enable
	// enable hash: /<uuid>/enable/hash
	httpServer.AddServiceEndpoint(path.Join(UUIDPath, string(EnableHash)),
		signingService.HandleRequest(EnableHash),
		false,
	)

	// delete:      /<uuid>/delete
	// delete hash: /<uuid>/delete/hash
	httpServer.AddServiceEndpoint(path.Join(UUIDPath, string(DeleteHash)),
		signingService.HandleRequest(DeleteHash),
		false,
	)

	// set up endpoints for verification
	verificationService := &VerificationService{
		Verify:        verify,
		VerifyOffline: verifyOffline,
	}

	// verify:              /verify
	// verify hash:         /verify/hash
	// verify offline:      /verify/offline
	// verify offline hash: /verify/offline/hash
	httpServer.AddServiceEndpoint(VerifyPath,
		verificationService.HandleRequest,
		true,
	)

	return httpServer
}

func (srv *HTTPServer) SetUpCORS(allowedOrigins []string, debug bool) {
	srv.Router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "X-Auth-Token"},
		ExposedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "X-Auth-Token"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
		Debug:            debug,
	}))
}

func HandleOptions(http.ResponseWriter, *http.Request) {}

func (srv *HTTPServer) AddServiceEndpoint(endpointPath string, handle func(offline, isHash bool) http.HandlerFunc, supportOffline bool) {
	hashEndpointPath := path.Join(endpointPath, HashEndpoint)

	srv.Router.Post(endpointPath, handle(false, false))
	srv.Router.Post(hashEndpointPath, handle(false, true))

	if supportOffline {
		offlineEndpointPath := path.Join(endpointPath, OfflinePath)
		offlineHashEndpointPath := path.Join(offlineEndpointPath, HashEndpoint)

		srv.Router.Post(offlineEndpointPath, handle(true, false))
		srv.Router.Post(offlineHashEndpointPath, handle(true, true))
	}

	srv.Router.Options(endpointPath, HandleOptions)
	srv.Router.Options(hashEndpointPath, HandleOptions)
}

func (srv *HTTPServer) Serve() error {
	cancelCtx, cancel := context.WithCancel(context.Background())
	go shutdown(cancel)

	server := &http.Server{
		Addr:         srv.Addr,
		Handler:      srv.Router,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

	go func() {
		<-cancelCtx.Done()
		server.SetKeepAlivesEnabled(false) // disallow clients to create new long-running conns

		shutdownWithTimeoutCtx, shutdownWithTimeoutCancel := context.WithTimeout(shutdownCtx, ShutdownTimeout)
		defer shutdownWithTimeoutCancel()
		defer shutdownCancel()

		if err := server.Shutdown(shutdownWithTimeoutCtx); err != nil {
			log.Warnf("could not gracefully shut down server: %s", err)
		} else {
			log.Debug("shut down HTTP server")
		}
	}()

	log.Infof("starting HTTP server")

	var err error
	if srv.TLS {
		err = server.ListenAndServeTLS(srv.CertFile, srv.KeyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("error starting HTTP server: %v", err)
	}

	// wait for server to shut down gracefully
	<-shutdownCtx.Done()
	return nil
}

// shutdown handles graceful shutdown of the server when SIGINT or SIGTERM is received
func shutdown(cancel context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Infof("shutting down after receiving: %v", sig)

	// cancel the contexts
	cancel()
}
