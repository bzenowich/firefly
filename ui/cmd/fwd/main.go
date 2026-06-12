// Command fwd is the firewall appliance daemon: HTTPS server, JSON API,
// server-rendered WebUI, and the declarative config engine (plan.md §7).
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"firewall/ui/internal/config"
	"firewall/ui/internal/server"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "listen address")
	confPath := flag.String("config", "fw.json", "path to config file")
	flag.Parse()

	store, err := config.Open(*confPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	srv, err := server.New(store)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	httpSrv := &http.Server{
		Addr:         *listen,
		Handler:      srv,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		log.Printf("fwd listening on http://%s", *listen)
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
