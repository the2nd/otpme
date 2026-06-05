// CSRF helper for JSON fetch() callers.
//
// Flask-WTF's CSRFProtect validates every state-mutating request and
// looks for the synchronizer token either as a `csrf_token` form field
// (rendered by `form.hidden_tag()` for HTML forms) or as an
// `X-CSRFToken` HTTP header. fetchJSON() wraps fetch() to attach the
// header automatically.
//
// The token is rendered into the page as `<meta name="csrf-token">`
// by base.html. It binds to the current Flask session and is not a
// secret in the cookie sense -- the protection works because
// Same-Origin-Policy keeps a third-party origin from reading the
// meta tag in the first place.

(function () {
    function csrfToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.content : '';
    }

    // fetchJSON(url, opts) -- drop-in fetch() replacement for JSON
    // requests. Sets Content-Type to application/json when sending a
    // body, attaches X-CSRFToken on state-mutating methods. Caller
    // supplies a JSON-stringified body in opts.body as usual.
    window.fetchJSON = function (url, opts) {
        opts = opts || {};
        const headers = Object.assign({}, opts.headers || {});
        const method = (opts.method || 'GET').toUpperCase();
        const stateMutating = (method !== 'GET'
                               && method !== 'HEAD'
                               && method !== 'OPTIONS');
        // Don't lie to the server about Content-Type on bodiless
        // requests (RFC 7231 ties it to the message body).
        if (opts.body !== undefined && !('Content-Type' in headers)) {
            headers['Content-Type'] = 'application/json';
        }
        if (stateMutating) {
            headers['X-CSRFToken'] = csrfToken();
        }
        return fetch(url, Object.assign({}, opts, {headers: headers}));
    };
})();
