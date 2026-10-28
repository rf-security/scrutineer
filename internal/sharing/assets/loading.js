// Polls the portal while the visitor's first GitHub repository lookup runs,
// then reloads the page they asked for. Served by the portal itself (not the
// shared /static/) because the page's CSP forbids inline scripts.
(function () {
  var detail = document.getElementById('detail');
  var retry = document.getElementById('retry');
  var spinner = document.getElementById('spinner');
  var bar = document.getElementById('bar');
  var failures = 0;

  retry.addEventListener('click', function () { location.reload(); });

  function fail(message) {
    detail.textContent = message;
    spinner.hidden = true;
    bar.hidden = true;
    retry.hidden = false;
  }

  function poll() {
    fetch('/auth/status', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (res) { return res.json(); })
      .then(function (st) {
        failures = 0;
        switch (st.state) {
          case 'ready':
          case 'idle':
            // idle: nothing running (e.g. the portal restarted); reloading
            // starts the lookup again.
            location.reload();
            return;
          case 'unauthorized':
            location.href = '/auth/login';
            return;
          case 'error':
            fail('GitHub did not respond. Your repositories could not be loaded.');
            return;
        }
        if (st.partial) {
          // The lookup has run long enough; the page is now served on the
          // repositories found so far and refreshes itself when done.
          location.reload();
          return;
        }
        if (st.found > 0) {
          detail.textContent = 'Found ' + st.found + ' ' +
            (st.found === 1 ? 'repository' : 'repositories') + ' so far…';
        }
        setTimeout(poll, 1000);
      })
      .catch(function () {
        if (++failures >= 5) {
          fail('Lost contact with the portal.');
          return;
        }
        setTimeout(poll, 2000);
      });
  }

  setTimeout(poll, 500);
})();
