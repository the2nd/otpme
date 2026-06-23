# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
Tiny WSGI app that publishes the Realm CA and the local Site CA
as PEM files over plain HTTP.

The whole point of this endpoint is bootstrap-trust: a client that
does not yet trust the OTPme PKI cannot use the HTTPS SSO host to
fetch the CAs (chicken-and-egg). Therefore this app deliberately
runs on a separate, plain-HTTP gunicorn instance with no auth, no
CSRF, no rate-limiter and no session state.

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

from flask import Flask
from flask import Response
from flask import abort
from flask import redirect
from flask import request
from flask import url_for
from markupsafe import escape

from otpme.lib import backend
from otpme.lib import config
from otpme.lib.pki.utils import get_cn


app = Flask(__name__)


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
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  height: 100%;
  font-family: 'Segoe UI', Roboto, Arial, sans-serif;
  font-size: 15px;
  color: #333;
  background: #f0f2f5;
}
body { display: flex; align-items: center; justify-content: center; padding: 24px; }
.card {
  background: #fff;
  border-radius: 12px;
  box-shadow: 0 2px 12px rgba(0,0,0,.08);
  padding: 36px 36px 28px;
  width: 100%;
  max-width: 520px;
}
h1 { font-size: 22px; font-weight: 600; color: #222; margin-bottom: 8px; }
.lead { font-size: 14px; color: #555; line-height: 1.55; margin-bottom: 22px; }
.cert-list { list-style: none; padding: 0; margin: 0 0 20px 0; }
.cert-list li {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border: 1px solid #e4e6ea;
  border-radius: 10px;
  background: #fafbfc;
  margin-bottom: 10px;
}
.cert-list .name { font-weight: 600; color: #222; }
.cert-list .desc { font-size: 12px; color: #666; margin-top: 2px; }
.cert-list a {
  display: inline-flex;
  align-items: center;
  padding: 8px 16px;
  border-radius: 8px;
  background: #4a7cff;
  color: #fff;
  font-weight: 600;
  font-size: 13px;
  text-decoration: none;
  transition: background .15s;
}
.cert-list a:hover { background: #3a66dd; }
.next-step {
  background: #eef5ff;
  border: 1px solid #c5d8ff;
  border-radius: 10px;
  padding: 12px 14px;
  font-size: 13px;
  color: #1f3a8a;
  margin-bottom: 18px;
  line-height: 1.5;
}
.next-step a {
  color: #1f3a8a;
  font-weight: 600;
  text-decoration: underline;
  word-break: break-all;
}
.hint {
  font-size: 12px;
  color: #888;
  border-top: 1px solid #eef0f3;
  padding-top: 14px;
  line-height: 1.55;
}
code {
  font-family: 'SFMono-Regular', Consolas, Menlo, monospace;
  font-size: 12px;
  background: #f5f7fa;
  padding: 1px 6px;
  border-radius: 4px;
}
</style>
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


@app.route('/')
def root():
    # The user-visible URL is /certs; bare / lands here.
    return redirect(url_for('index'))


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


@app.route('/certs')
@app.route('/certs/')
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


@app.route('/certs/realm_ca.pem')
def realm_ca():
    pem = _extract_cert_by_cn(_get_ca_data(), config.realm_ca_path)
    if not pem:
        abort(404)
    return _pem_response(pem, 'realm_ca.pem')


@app.route('/certs/site_ca.pem')
def site_ca():
    pem = _extract_cert_by_cn(_get_ca_data(), config.site_ca_path)
    if not pem:
        abort(404)
    return _pem_response(pem, 'site_ca.pem')
