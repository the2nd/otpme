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
        // Accept hint -- some endpoints (CSRF error handler) sniff this
        // to pick a JSON error body over the default HTML 400.
        if (!('Accept' in headers)) {
            headers['Accept'] = 'application/json';
        }
        if (stateMutating) {
            headers['X-CSRFToken'] = csrfToken();
        }
        return fetch(url, Object.assign({}, opts, {headers: headers}));
    };

    // readJsonResponse(resp, fallbackLabel) -- safely consume a
    // fetchJSON response that may or may not actually carry JSON.
    // Returns {body, error}:
    //   - body: parsed JSON dict on success, else null.
    //   - error: human-readable string when the response is non-2xx,
    //     not application/json, has a redirected URL (fetch silently
    //     followed a 302 to /login), or fails to parse. The server's
    //     own `error` field is preferred, with the CSRF error handler's
    //     "Your session expired..." surfacing here on token expiry.
    //
    // Without this helper, `await resp.json()` on a Flask flash+redirect
    // (302 to /login) or a CSRF 400 HTML page raises the unhelpful
    // "JSON.parse: unexpected character at line 1 column 1" the user
    // sees in DevTools.
    window.readJsonResponse = async function (resp, fallbackLabel) {
        const ct = (resp.headers.get('Content-Type') || '').toLowerCase();
        let body = null;
        if (ct.includes('application/json')) {
            try {
                body = await resp.json();
            } catch (e) {
                body = null;
            }
        }
        if (resp.ok && body !== null) {
            return {body: body, error: null};
        }
        // Session expiry: the Flask side emits 401 + JSON
        // {error, redirect, session_expired} when @login_required
        // fires on an idle tab (or the SSO JWT is invalid). Navigate
        // to /login instead of surfacing "Unauthorized" -- without
        // this the user sees a bare error string and has to find the
        // login page themselves. `replace()` so the dead settings URL
        // doesn't sit in browser history.
        if (resp.status === 401 && body && body.redirect) {
            window.location.replace(body.redirect);
            // Navigation is async; return a non-error result so the
            // caller's catch path doesn't flash a message in the UI
            // before the page swaps.
            return {body: body, error: null};
        }
        let error = body && body.error;
        if (!error) {
            if (resp.redirected) {
                error = (fallbackLabel || 'Request failed.')
                        + ' (HTTP ' + resp.status + ', redirected)';
            } else {
                error = (fallbackLabel || 'Request failed.')
                        + ' (HTTP ' + resp.status + ')';
            }
        }
        return {body: body, error: error};
    };
})();
