// Command fwd is the firewall appliance daemon: HTTPS server, JSON API,
// server-rendered WebUI, and the declarative config engine (plan.md §7).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"firewall/ui/internal/apply"
	"firewall/ui/internal/cert"
	"firewall/ui/internal/config"
	"firewall/ui/internal/flow"
	"firewall/ui/internal/logs"
	"firewall/ui/internal/server"
	"firewall/ui/internal/traffic"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "HTTPS listen address")
	httpListen := flag.String("http", "", "optional HTTP listen address that redirects to HTTPS (e.g. :80)")
	confPath := flag.String("config", "fw.json", "path to config file")
	window := flag.Duration("confirm-window", time.Minute, "auto-rollback window after apply (0 = no confirmation step)")
	flag.Parse()

	store, err := config.Open(*confPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Self-signed TLS identity lives next to the config file; generated at
	// first boot, stable afterwards so the browser exception sticks.
	dir := filepath.Dir(*confPath)
	cfg := store.Get()
	var ips []net.IP
	if lan := cfg.LAN(); lan.IPv4 != "" {
		if ip, _, err := net.ParseCIDR(lan.IPv4); err == nil {
			ips = append(ips, ip)
		}
	}
	ips = append(ips, net.ParseIP("127.0.0.1"))
	tlsCert, err := cert.Ensure(filepath.Join(dir, "fw-cert.pem"), filepath.Join(dir, "fw-key.pem"),
		cfg.System.Hostname, ips)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	// Off-FreeBSD, apply renders into ./devroot and logs service commands
	// instead of executing them, so the pipeline is exercisable on a dev box.
	sys := apply.OSSystem{}
	if runtime.GOOS != "freebsd" {
		sys = apply.OSSystem{Root: "devroot", NoExec: true}
		log.Printf("non-FreeBSD host: apply writes to ./devroot, commands logged only")
	}
	mgr := apply.New(sys, *window)

	// Log ring buffer lives next to the config; collectors only exist on
	// FreeBSD (tcpdump on pflog0, tail on syslog files).
	logStore, err := logs.Open(filepath.Join(dir, "fw-logs.db"), 50000)
	if err != nil {
		log.Fatalf("logs: %v", err)
	}
	defer logStore.Close()
	collectCtx, stopCollect := context.WithCancel(context.Background())
	defer stopCollect()
	if runtime.GOOS == "freebsd" {
		logs.NewCollector(logStore).Run(collectCtx)
	}

	// Throughput history for the Traffic page. The sampler reads kernel byte
	// counters cross-platform, so it runs on the dev box too.
	trafStore, err := traffic.Open(filepath.Join(dir, "fw-traffic.db"))
	if err != nil {
		log.Fatalf("traffic: %v", err)
	}
	defer trafStore.Close()
	go traffic.NewSampler(trafStore).Run(collectCtx)

	// Baseline network visibility: the flow collector receives pflow's IPFIX
	// export on localhost and summarizes flows into SQLite for the Visibility
	// page. Pure Go + kernel; runs cross-platform like the traffic sampler,
	// though only the FreeBSD appliance's pflow(4) actually exports to it.
	flowStore, err := flow.Open(filepath.Join(dir, "fw-flows.db"))
	if err != nil {
		log.Fatalf("flow: %v", err)
	}
	defer flowStore.Close()
	flowAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Flow.CollectorPort()))
	go func() {
		if err := flow.NewCollector(flowStore, flowAddr).Run(collectCtx); err != nil {
			log.Printf("flow collector: %v", err)
		}
	}()

	srv, err := server.New(store, mgr, logStore, trafStore, flowStore)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	httpSrv := &http.Server{
		Addr:         *listen,
		Handler:      srv,
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		log.Printf("fwd listening on https://%s", *listen)
		if err := httpSrv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	if *httpListen != "" {
		_, port, _ := net.SplitHostPort(*listen)
		go func() {
			err := http.ListenAndServe(*httpListen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host, _, err := net.SplitHostPort(r.Host)
				if err != nil {
					host = r.Host
				}
				http.Redirect(w, r, "https://"+net.JoinHostPort(host, port)+r.URL.RequestURI(), http.StatusMovedPermanently)
			}))
			log.Fatalf("http redirect listener: %v", err)
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
