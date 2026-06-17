package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"
)

// probeTimeout caps every live test so a dead server can't hang the request.
const probeTimeout = 3 * time.Second

// probeDNS measures a resolver's responsiveness. With a hostname it dials
// DNS-over-TLS on :853 and verifies the certificate against that name (the
// "TLS OK" note proves verification passed); without one it times a plain UDP
// query on :53. The returned duration is the measured round trip.
func probeDNS(address, hostname string) (time.Duration, string, error) {
	if hostname != "" {
		start := time.Now()
		dialer := &net.Dialer{Timeout: probeTimeout}
		conn, err := tls.DialWithDialer(dialer, "tcp",
			net.JoinHostPort(address, "853"), &tls.Config{ServerName: hostname})
		if err != nil {
			return 0, "", err
		}
		conn.Close()
		return time.Since(start), "TLS OK", nil
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(address, "53"), probeTimeout)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))
	start := time.Now()
	if _, err := conn.Write(dnsQuery("example.com")); err != nil {
		return 0, "", err
	}
	if _, err := conn.Read(make([]byte, 512)); err != nil {
		return 0, "", err
	}
	return time.Since(start), "", nil
}

// dnsQuery builds a minimal DNS A-record query for name. A fixed transaction
// ID is fine: we only time the round trip, not match the reply.
func dnsQuery(name string) []byte {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0} // RD set, 1 question
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0x00)       // root label
	b = append(b, 0x00, 0x01) // QTYPE A
	b = append(b, 0x00, 0x01) // QCLASS IN
	return b
}

// probeNTP times an SNTP request/response to a time source. server may be a
// bare host (port 123 assumed) or host:port.
func probeNTP(server string) (time.Duration, error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "123")
	}
	conn, err := net.DialTimeout("udp", addr, probeTimeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))
	req := make([]byte, 48)
	req[0] = 0x1b // LI=0, VN=3, Mode=3 (client)
	start := time.Now()
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}
	if _, err := conn.Read(make([]byte, 48)); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// writeProbeResult renders the latency badge htmx swaps into a test cell.
func writeProbeResult(w http.ResponseWriter, d time.Duration, note string, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err != nil {
		fmt.Fprintf(w, `<span class="bad">%s</span>`, template.HTMLEscapeString(probeErr(err)))
		return
	}
	label := fmt.Sprintf("%d ms", d.Milliseconds())
	if note != "" {
		label += " · " + note
	}
	fmt.Fprintf(w, `<span class="ok">%s</span>`, template.HTMLEscapeString(label))
}

// probeErr collapses a network error into a short, user-facing reason.
func probeErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	if strings.Contains(err.Error(), "certificate") {
		return "TLS verify failed"
	}
	return "unreachable"
}
