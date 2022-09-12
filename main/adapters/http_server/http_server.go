package http_server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"

	log "github.com/sirupsen/logrus"
	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
)

type HTTPServer struct {
	Router   *chi.Mux
	Addr     string
	TLS      bool
	CertFile string
	KeyFile  string
}

func NewRouter() *chi.Mux {
	router := chi.NewMux()
	router.Use(prom.PromMiddleware)
	router.Use(middleware.Timeout(GatewayTimeout))
	return router
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
