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
  // Rows are built as DOM nodes, never as HTML strings.
  //
  // Everything in this table comes off the wire: hostnames from DNS, app labels
  // that nDPI read out of a TLS SNI or an HTTP Host header — that is, out of
  // whatever a remote server chose to send. This page previously assembled
  // markup and passed it through a local escaper covering & < >, which is
  // sufficient for text position and silently is not the moment anyone moves a
  // value into an attribute. textContent cannot be got wrong that way
  // (docs/security-plan.md SEC-13).
  //
  // The labels are also constrained at ingest (flow.SanitizeApp); this is the
  // second of the two defenses, and the one that survives someone adding a
  // column.
  function cell(text, cls) {
    var td = document.createElement("td");
    td.textContent = text;
    if (cls) td.className = cls;
    return td;
  }

  function row(cells) {
    var tr = document.createElement("tr");
    cells.forEach(function (td) { tr.appendChild(td); });
    return tr;
  }

  function emptyRow(cols) {
    var tr = document.createElement("tr");
    var td = cell("no data yet", "muted");
    td.colSpan = cols;
    tr.appendChild(td);
    return tr;
  }

  function fill(id, rows, cols) {
    var body = document.querySelector("#" + id + " tbody");
    body.replaceChildren.apply(body, rows.length ? rows : [emptyRow(cols)]);
  }

  function render(d) {
    fill("flow-talkers", (d.talkers || []).map(function (t) {
      return row([
        cell(t.host),
        cell(fmtBytes(t.in), "num"),
        cell(fmtBytes(t.out), "num"),
        cell(fmtBytes(t.in + t.out), "num"),
      ]);
    }), 4);

    fill("flow-apps", (d.apps || []).map(function (a) {
      return row([cell(a.app), cell(fmtBytes(a.bytes), "num")]);
    }), 2);

    fill("flow-recent", (d.recent || []).map(function (f) {
      return row([
        cell(fmtTime(f.t)),
        cell(f.src + ":" + f.sport),
        cell(f.dst + ":" + f.dport),
        cell(fmtProto(f.proto)),
        cell(fmtBytes(f.bytes), "num"),
        cell(String(f.pkts), "num"),
      ]);
    }), 6);
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
