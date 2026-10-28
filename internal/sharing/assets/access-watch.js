// Loaded only on pages served from a partial repository list (the GitHub
// lookup outlasted the progress page). Polls the portal and reloads once the
// lookup has finished so the full set of repositories appears.
(function () {
  function poll() {
    fetch('/auth/status', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (res) { return res.json(); })
      .then(function (st) {
        if (st.state === 'loading') {
          setTimeout(poll, 3000);
          return;
        }
        if (st.state === 'ready' || st.state === 'unauthorized') {
          // unauthorized: the reload lands on the login redirect.
          location.reload();
        }
        // error / idle: stop; the next navigation retries the lookup.
      })
      .catch(function () { setTimeout(poll, 10000); });
  }
  setTimeout(poll, 3000);
})();
