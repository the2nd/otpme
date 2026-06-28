# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
Tiny WSGI app that publishes the Realm CA and the local Site CA
as PEM files.

The whole point of this endpoint is bootstrap-trust: a client that
does not yet trust the OTPme PKI cannot use the HTTPS SSO host to
fetch the CAs (chicken-and-egg). Therefore the routes are exposed
as a Flask Blueprint that is mounted on both the plain-HTTP gunicorn
instance (for the bootstrap case -- no auth, no CSRF, no session)
and on the HTTPS SSO app (so the same URL keeps working once the
trust store has the CA).

The certs themselves are public material; serving them unauthenticated
over HTTP is the standard pattern (cf. Let's Encrypt's chain.pem,
distributors' CA bundles). Operators are expected to compare the
fingerprint out-of-band before placing the cert into their trust
store.

Source of truth: ``realm.ca_data`` -- a concatenated PEM blob written
by ``Realm.update_ca_data()`` that contains the Realm CA cert + CRL
followed by every Site CA cert + CRL of the realm. The blob is
replicated to every host as part of the standard realm-object sync,
so this endpoint serves whatever the local backend currently has.
"""
import re

from flask import Blueprint
from flask import Flask
from flask import Response
from flask import abort
from flask import redirect
from flask import request
from markupsafe import escape

from otpme.lib import backend
from otpme.lib import config
from otpme.lib.pki.utils import get_cn


# Blueprint mounted at /certs on both the standalone HTTP app below
# and the main HTTPS app (see otpme/lib/daemon/httpd.py).
#
# CSS lives in a static file (not inline) because the HTTPS app sets
# ``Content-Security-Policy: style-src 'self'`` -- which allows
# same-origin stylesheets via <link> but blocks inline <style>.
bp = Blueprint(
    'certs',
    __name__,
    static_folder='static',
    static_url_path='/static',
)


# Match a single PEM CERTIFICATE block. CRLs and other PEM types
# (BEGIN X509 CRL / BEGIN PRIVATE KEY / ...) inside ca_data are
# deliberately ignored -- a trust store wants the cert, not the
# revocation list.
_PEM_CERT_RE = re.compile(
    r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
    re.DOTALL,
)


_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OTPme CA certificates</title>
<link rel="stylesheet" href="/certs/static/certs.css">
</head>
<body>
<div class="card">
<h1>OTPme CA certificates</h1>
<p class="lead">Download the CA certificates of this OTPme realm and site.
Use them to populate the trust store of clients that need to validate
TLS certificates issued by this PKI.</p>
__NEXT_STEP__
<ul class="cert-list">
  <li>
    <div>
      <div class="name">Realm CA</div>
      <div class="desc">Root of the OTPme realm PKI.</div>
    </div>
    <a href="/certs/realm_ca.pem">realm_ca.pem</a>
  </li>
  <li>
    <div>
      <div class="name">Site CA</div>
      <div class="desc">Intermediate CA of the local site.</div>
    </div>
    <a href="/certs/site_ca.pem">site_ca.pem</a>
  </li>
</ul>
<p class="hint">Verify the fingerprint out-of-band before trusting these
files. Quick check: <code>openssl x509 -noout -fingerprint -sha256 -in &lt;file&gt;</code>.</p>
</div>
</body>
</html>
"""


def _get_ca_data():
    """ Read the realm's CA bundle from the local backend. Returns
    the raw concatenated PEM string or None. """
    if not config.realm_uuid:
        return None
    realm = backend.get_object(uuid=config.realm_uuid,
                                object_type="realm")
    if not realm:
        return None
    return getattr(realm, "ca_data", None) or None


def _extract_cert_by_cn(ca_data, target_cn):
    """ Pull the first CERTIFICATE block whose Subject CN equals
    ``target_cn``. Each Realm/Site CA carries its OTPme object path
    as CN (see ``Site.create_site_ca`` and ``Realm.init``), so the
    lookup is deterministic. """
    if not ca_data or not target_cn:
        return None
    for match in _PEM_CERT_RE.finditer(ca_data):
        pem = match.group(0)
        try:
            cn = get_cn(pem)
        except Exception:
            # Malformed block -- skip, don't abort the whole search.
            continue
        if cn == target_cn:
            # Re-emit with a trailing newline so consumers that
            # concatenate files don't end up with two PEM headers
            # glued on one line.
            if not pem.endswith("\n"):
                pem = pem + "\n"
            return pem
    return None


def _pem_response(pem, filename):
    # ``application/x-pem-file`` is the de-facto MIME type for PEM
    # bundles; ``Content-Disposition: attachment`` makes browsers
    # download instead of trying to render the certificate body.
    resp = Response(pem, mimetype='application/x-pem-file')
    resp.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    resp.headers['Cache-Control'] = 'no-store'
    return resp


def _https_url():
    """ Build the HTTPS URL of the SSO portal for the post-install
    hint on the index page.

    Prefers ``config.site_sso_fqdn`` (the canonical SSO hostname
    operators configured at site creation); falls back to the Host
    header the request arrived on (minus port) so a deployment that
    didn't set site_sso_fqdn still gets a useful link. Returns None
    when neither is available -- the hint is then omitted entirely
    rather than rendered with a half-broken URL. """
    host = getattr(config, "site_sso_fqdn", None)
    if not host:
        host = (request.host or "").split(":", 1)[0]
    if not host:
        return None
    return f"https://{host}/"


@bp.route('/')
def index():
    url = _https_url()
    if url:
        safe = escape(url)
        next_step = (
            '<div class="next-step">'
            'Once you’ve installed these certificates into your trust '
            'store, you can switch to the secure portal at '
            f'<a href="{safe}">{safe}</a>.'
            '</div>'
        )
    else:
        next_step = ''
    html = _INDEX_HTML.replace('__NEXT_STEP__', next_step)
    resp = Response(html, mimetype='text/html; charset=utf-8')
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@bp.route('/realm_ca.pem')
def realm_ca():
    pem = _extract_cert_by_cn(_get_ca_data(), config.realm_ca_path)
    if not pem:
        abort(404)
    return _pem_response(pem, 'realm_ca.pem')


@bp.route('/site_ca.pem')
def site_ca():
    pem = _extract_cert_by_cn(_get_ca_data(), config.site_ca_path)
    if not pem:
        abort(404)
    return _pem_response(pem, 'site_ca.pem')


# Standalone Flask app used by the plain-HTTP gunicorn instance.
# Mounting the blueprint here gives /certs/* exactly the same routes
# the HTTPS app exposes after registering ``bp``.
app = Flask(__name__)
app.register_blueprint(bp, url_prefix='/certs')


@app.route('/')
def root():
    # Bare / on the plain-HTTP instance lands users on /certs/.
    return redirect('/certs/')
