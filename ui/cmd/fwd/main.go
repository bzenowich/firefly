// Command fwd is the firewall appliance daemon: HTTPS server, JSON API,
// server-rendered WebUI, and the declarative config engine (plan.md §7).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
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

	"firewall/ui/internal/cert"
	"firewall/ui/internal/config"
	"firewall/ui/internal/flow"
	"firewall/ui/internal/logs"
	"firewall/ui/internal/privsep"
	"firewall/ui/internal/server"
	"firewall/ui/internal/traffic"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", `HTTPS listen address, or "auto" for the LAN address`)
	httpListen := flag.String("http", "", "optional HTTP listen address that redirects to HTTPS (e.g. :80)")
	confPath := flag.String("config", "fw.json", "path to config file")
	helperSocket := flag.String("helper-socket", "/var/run/fwd-helper.sock", "unix socket of the privileged helper (fwd-helper)")
	labelSocket := flag.String("label-socket", "", "unix socket the ndpi-helper streams app labels to (default: next to the config)")
	labelPeer := flag.String("label-peer", "", "account the ndpi-helper runs as; restricts the label socket to it (recommended: _fwdpcap)")
	flag.Parse()

	if err := os.Setenv("PATH", appliancePath); err != nil {
		log.Fatalf("setting PATH: %v", err)
	}

	store, err := config.Open(*confPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Self-signed TLS identity lives next to the config file; generated at
	// first boot, stable afterwards so the browser exception sticks.
	dir := filepath.Dir(*confPath)
	if *labelSocket == "" {
		// Default next to the other state. On the appliance rc.d puts it in
		// /var/run instead, because the state directory is mode 0700 and the
		// classifier runs as a different account.
		*labelSocket = filepath.Join(dir, "fw-ndpi.sock")
	}
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

	// "auto" binds the LAN address rather than every interface. The admin UI
	// on 0.0.0.0 was reachable from the WAN and invisible only because pf
	// blocked it first; not listening there is a property of the process
	// rather than of the ruleset (docs/security-plan.md SEC-5).
	if *listen == "auto" {
		addr, err := autoListen(cfg)
		if err != nil {
			log.Fatalf("listen=auto: %v", err)
		}
		*listen = addr
		log.Printf("binding the LAN address only: %s", *listen)
	}

	// The privileged boundary (internal/privsep). Every privileged operation
	// goes to fwd-helper; this process performs none itself and holds no
	// privilege with which to try.
	//
	// There is deliberately no in-process fallback. One existed while the split
	// was being brought up (docs/security-plan.md §3.5) and it is gone: a
	// fallback is a way for a misconfiguration to silently produce a root web
	// daemon, which is the exact outcome the split exists to prevent. If the
	// helper is unreachable, privileged operations fail with a message saying
	// so — loudly, and without doing them.
	//
	// The practical consequence for development is that fwd needs fwd-helper
	// alongside it. That is a feature: it is the same path the appliance runs,
	// and `fwd-helper -root ./devroot -noexec` gives a dev box the whole
	// pipeline without touching the system.
	client := privsep.NewClient(*helperSocket)
	var (
		priv  privsep.Ops         = client
		shell privsep.ShellOpener = client
		wgSt  privsep.WGStatus    = client
	)
	log.Printf("privileged operations go to fwd-helper at %s", *helperSocket)

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

	// App-layer enrichment: the ndpi-helper streams {5-tuple → app} labels to
	// the LabelServer over a unix socket; the collector stamps them onto flows
	// at insert (docs/ndpi-helper-design.md). The socket lives next to the other
	// state files so it is writable on dev and appliance alike.
	labelCache := flow.NewLabelCache()
	labelSrv := flow.NewLabelServer(*labelSocket, labelCache, flowStore)
	if *labelPeer != "" {
		// The classifier runs as its own account, so the socket is shared with
		// exactly that one and connections from anything else are refused.
		labelSrv = labelSrv.WithPeer(*labelPeer)
	}
	go func() {
		if err := labelSrv.Run(collectCtx); err != nil {
			log.Printf("flow label server: %v", err)
		}
	}()
	go func() {
		if err := flow.NewCollector(flowStore, flowAddr).WithLabels(labelCache).Run(collectCtx); err != nil {
			log.Printf("flow collector: %v", err)
		}
	}()

	// ndpi-helper is NOT started here. It is its own rc.d service
	// (os/rc.d/ndpi-helper) running as _fwdpcap, because fwd is unprivileged
	// after the split and cannot fork anything as another account — and
	// because a libnDPI process parsing hostile frames should not inherit the
	// web daemon's identity either (docs/security-plan.md SEC-2a). fwd's only
	// relationship to it is the label socket the LabelServer above listens on.

	srv, err := server.New(store, priv, shell, wgSt, logStore, trafStore, flowStore)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	// Timeout policy (design-review §4.3). ReadTimeout/WriteTimeout arm absolute
	// deadlines on the connection the moment a request starts, which is wrong for
	// the two long-lived routes: the web shell hijacks its connection for a whole
	// terminal session, and the ntopng proxy relays responses of unknown length.
	// Both clear their own deadlines with http.ResponseController before they
	// take over the connection, so the blanket values stay as the default for
	// every ordinary page. ReadHeaderTimeout bounds the slow-header attack on its
	// own; IdleTimeout reaps kept-alive connections.
	//
	// NextProtos pins HTTP/1.1: ListenAndServeTLS would otherwise negotiate
	// HTTP/2, whose ResponseWriter implements neither Hijacker (the web shell's
	// WebSocket upgrade needs it) nor deadline control.
	httpSrv := &http.Server{
		Addr:    *listen,
		Handler: srv,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			// TLS 1.2 is the floor rather than 1.3 because the appliance is
			// managed from whatever browser the owner has, and an admin locked
			// out of their firewall by a handshake failure is a worse outcome
			// than a 1.2 session. The cipher list is what makes 1.2 acceptable:
			// AEAD suites with forward secrecy only, so the weak end of what
			// 1.2 permits is not on offer (docs/security-plan.md SEC-17).
			// CipherSuites is ignored for 1.3, whose suites are all acceptable.
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			NextProtos: []string{"http/1.1"},
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	go func() {
		log.Printf("fwd listening on https://%s", *listen)
		if err := httpSrv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	if *httpListen != "" {
		_, port, _ := net.SplitHostPort(*listen)
		// The redirect target is the appliance's own address, never the Host
		// the client sent.
		//
		// Echoing r.Host meant an attacker could hand someone a link to the
		// firewall's HTTP port carrying any Host they liked and have the
		// appliance itself issue the redirect to it — the firewall lending its
		// name to somewhere else, with a 301 the browser then caches
		// (docs/security-plan.md SEC-17). The LAN address is the one the admin
		// reaches the box on; the hostname is a fallback for a box whose LAN
		// address is not yet configured.
		target := redirectHost(store.Get())
		go func() {
			err := http.ListenAndServe(*httpListen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+net.JoinHostPort(target, port)+r.URL.RequestURI(),
					http.StatusFound)
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

// appliancePath is the PATH this daemon runs external commands with.
//
// rc.d starts services through daemon(8), which passes on the boot environment:
// PATH=/sbin:/bin:/usr/sbin:/usr/bin. Every package-installed tool the appliance
// depends on lives outside that — kea-dhcp4 and unbound-checkconf in
// /usr/local/sbin, wg in /usr/local/bin — so with the inherited PATH the very
// first apply fails at the kea validator with "executable file not found", and
// the WireGuard page silently reports no handshakes.
//
// It is set here, once, rather than at each exec site, so a command added later
// cannot miss it. Found on the VM: it does not reproduce when the daemon is
// started by hand from a login shell, which is how it stayed hidden.
const appliancePath = "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"

// redirectHost is the appliance's own name for the HTTP->HTTPS redirect: its
// LAN address, or its hostname when the LAN has no address yet.
func redirectHost(cfg config.Config) string {
	if lan := cfg.LAN(); lan.IPv4 != "" {
		if ip, _, err := net.ParseCIDR(lan.IPv4); err == nil {
			return ip.String()
		}
	}
	if cfg.System.Hostname != "" {
		return cfg.System.Hostname
	}
	return "127.0.0.1"
}

// autoListen resolves the LAN address to bind, with the WebUI's port.
//
// It is an error rather than a fallback to 0.0.0.0 when the LAN has no address:
// silently binding everything is the behaviour this exists to remove, and doing
// it as a "helpful" fallback is how it would come back.
func autoListen(cfg config.Config) (string, error) {
	lan := cfg.LAN()
	if lan.IPv4 == "" {
		return "", fmt.Errorf("the lan interface has no address yet; set one, or pass an explicit -listen")
	}
	ip, _, err := net.ParseCIDR(lan.IPv4)
	if err != nil {
		return "", fmt.Errorf("lan address %q: %w", lan.IPv4, err)
	}
	port := 8443
	if ports := cfg.System.Management.ManagementPorts(); len(ports) > 0 {
		port = ports[0]
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}
