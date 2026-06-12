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
	"runtime"
	"syscall"
	"time"

	"firewall/ui/internal/apply"
	"firewall/ui/internal/config"
	"firewall/ui/internal/server"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "listen address")
	confPath := flag.String("config", "fw.json", "path to config file")
	window := flag.Duration("confirm-window", time.Minute, "auto-rollback window after apply (0 = no confirmation step)")
	flag.Parse()

	store, err := config.Open(*confPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Off-FreeBSD, apply renders into ./devroot and logs service commands
	// instead of executing them, so the pipeline is exercisable on a dev box.
	sys := apply.OSSystem{}
	if runtime.GOOS != "freebsd" {
		sys = apply.OSSystem{Root: "devroot", NoExec: true}
		log.Printf("non-FreeBSD host: apply writes to ./devroot, commands logged only")
	}
	mgr := apply.New(sys, *window)

	srv, err := server.New(store, mgr)
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
