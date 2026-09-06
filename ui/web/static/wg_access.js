// Extracted from templates/pages/wg_access.html so the admin UI can run under a
// Content-Security-Policy of script-src 'self' — no inline script anywhere, and
// no on* attributes, which the same directive blocks (docs/security-plan.md
// SEC-8).
(function () {
  "use strict";
  var list = document.getElementById('svc-list');
  if (!list) return; // no services defined yet: the page renders a hint instead

  function rows() { return Array.prototype.slice.call(list.querySelectorAll('.svc')); }

  function filterSvc() {
    var q = document.getElementById('svc-filter').value.toLowerCase();
    rows().forEach(function (li) {
      li.style.display = li.textContent.toLowerCase().indexOf(q) === -1 ? 'none' : '';
    });
  }

  // Bulk actions apply to the currently shown (filtered) rows, so you can
  // filter "web" then grant them all in one click.
  function setVisible(on) {
    rows().forEach(function (li) {
      if (li.style.display !== 'none') li.querySelector('input').checked = on;
    });
    updateCount();
  }

  function updateCount() {
    var boxes = list.querySelectorAll('input[type=checkbox]');
    var on = list.querySelectorAll('input[type=checkbox]:checked').length;
    document.getElementById('svc-count').textContent = on + ' of ' + boxes.length + ' granted';
  }

  document.getElementById('svc-filter').addEventListener('input', filterSvc);
  document.getElementById('svc-select-shown').addEventListener('click', function () { setVisible(true); });
  document.getElementById('svc-clear-shown').addEventListener('click', function () { setVisible(false); });
  // One delegated listener beats one per checkbox, and it survives the list
  // being re-rendered.
  list.addEventListener('change', updateCount);

  updateCount();
})();
