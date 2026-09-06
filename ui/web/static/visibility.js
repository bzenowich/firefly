// Extracted from templates/pages/visibility.html so the admin UI can run under a
// Content-Security-Policy of script-src 'self' — no inline script anywhere
// (docs/security-plan.md SEC-8).
(function () {
  "use strict";
  if (!document.getElementById("flow-status")) return; // baseline disabled
  var range = "hour";
  var refreshMs = { hour: 10000, day: 30000, week: 60000, month: 60000 };
  var timer = null;

  function fmtBytes(n) {
    var u = ["B", "K", "M", "G", "T"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + " " + u[i];
  }
  var PROTO = { 1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMP6" };
  function fmtProto(p) { return PROTO[p] || String(p); }
  function fmtTime(t) {
    var d = new Date(t * 1000), p = function (n) { return (n < 10 ? "0" : "") + n; };
    return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }
  function esc(s) {
    return String(s).replace(/[&<>]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c];
    });
  }
  function fill(id, rows) {
    var body = document.querySelector("#" + id + " tbody");
    body.innerHTML = rows.length ? rows.join("") :
      '<tr><td colspan="6" class="muted">no data yet</td></tr>';
  }

  function render(d) {
    fill("flow-talkers", (d.talkers || []).map(function (t) {
      return "<tr><td>" + esc(t.host) + "</td><td class='num'>" + fmtBytes(t.in) +
        "</td><td class='num'>" + fmtBytes(t.out) + "</td><td class='num'>" +
        fmtBytes(t.in + t.out) + "</td></tr>";
    }));
    fill("flow-apps", (d.apps || []).map(function (a) {
      return "<tr><td>" + esc(a.app) + "</td><td class='num'>" + fmtBytes(a.bytes) + "</td></tr>";
    }));
    fill("flow-recent", (d.recent || []).map(function (f) {
      return "<tr><td>" + fmtTime(f.t) + "</td><td>" + esc(f.src) + ":" + f.sport +
        "</td><td>" + esc(f.dst) + ":" + f.dport + "</td><td>" + fmtProto(f.proto) +
        "</td><td class='num'>" + fmtBytes(f.bytes) + "</td><td class='num'>" + f.pkts + "</td></tr>";
    }));
  }

  function load() {
    fetch("/api/flows?range=" + range, { headers: { "HX-Request": "true" } })
      .then(function (r) {
        if (r.status === 401) { window.location = "/login"; return null; }
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (d) {
        if (!d) return;
        render(d);
        document.getElementById("flow-status").textContent =
          "updated " + new Date().toLocaleTimeString();
      })
      .catch(function (e) {
        document.getElementById("flow-status").textContent = "error: " + e.message;
      });
  }
  function schedule() {
    if (timer) clearInterval(timer);
    timer = setInterval(load, refreshMs[range] || 30000);
  }
  document.querySelectorAll(".traffic-ranges button").forEach(function (b) {
    b.addEventListener("click", function () {
      range = b.dataset.range;
      document.querySelectorAll(".traffic-ranges button").forEach(function (x) {
        x.classList.toggle("active", x === b);
      });
      load(); schedule();
    });
  });
  load(); schedule();
})();
