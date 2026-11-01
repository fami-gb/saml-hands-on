"""IdP（ポート5000）。uv run --with flask --with cryptography idp.py"""
import base64
import html
import zlib

from cryptography.hazmat.primitives import serialization
from flask import Flask, abort, request

import saml_lib as s

ISSUER = "http://localhost:5000"
SSO_URL = ISSUER + "/sso"
# SPの事前登録（entity ID → ACS URL）。応答の送り先はリクエストではなく、ここから決める
SPS = {"http://localhost:5001": "http://localhost:5001/acs"}
# ponytail: 平文パスワードの固定ユーザー。本物はハッシュ化してDBに
USERS = {
    "alice": ("alice", {"mail": "alice@example.com", "role": "admin"}),
    "bob": ("bob", {"mail": "bob@example.com", "role": "user"}),
}
# ponytail: 起動ごとに鍵が変わる。第6回でファイルに保存する
priv, pub = s.generate_keypair()

app = Flask(__name__)
app.after_request(s.no_cache)


@app.get("/metadata")
def metadata():
    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"entity_id": ISSUER, "sso_url": SSO_URL, "public_key": pem.decode()}


def parse_authn_request(saml_request):
    """HTTP-Redirect binding の逆: base64 → raw inflate → XML。(リクエストID, SPのID, ACS URL) を返す。"""
    try:
        req = s.parse_xml(zlib.decompress(base64.b64decode(saml_request), -15).decode())
    except (s.SamlError, ValueError, zlib.error):
        abort(400, "SAMLRequestを読めない")
    if not req.get("ID"):
        abort(400, "IDがない")
    if req.get("Destination") not in (None, SSO_URL):
        abort(400, "Destinationが自分ではない")
    issuer = req.find(f"{{{s.NS}}}Issuer")
    acs = SPS.get(issuer.text if issuer is not None else None)
    if acs is None:
        abort(400, "未登録のSP")
    if req.get("AssertionConsumerServiceURL") not in (None, acs):
        abort(400, "ACS URLが登録と違う")
    return req.get("ID"), issuer.text, acs


def post_form(response, acs):
    """HTTP-POST binding: ブラウザに自動送信フォームを返し、ブラウザ経由でSPのACSに届ける。"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="ja">
<head><title>SAML</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="{html.escape(acs)}">
<div><input type="hidden" name="SAMLResponse" value="{base64.b64encode(response.encode()).decode()}"/></div>
<noscript><div><input type="submit" value="続ける"/></div></noscript>
</form>
</body>
</html>"""


@app.route("/sso", methods=["GET", "POST"])
def sso():
    saml_request = request.values.get("SAMLRequest") or abort(400, "SAMLRequestがない")
    req_id, sp_id, acs = parse_authn_request(saml_request)

    if request.form.get("cancel"):
        return post_form(s.build_response("", acs, req_id, status=s.STATUS_RESPONDER, issuer=ISSUER), acs)

    username = request.form.get("username", "")
    user = USERS.get(username)
    if request.method == "GET" or user is None or user[0] != request.form.get("password"):
        error = "" if request.method == "GET" else "<p style='color:red'>ユーザー名かパスワードが違います</p>"
        return f"""<h1>IdP ログイン</h1><p>{html.escape(sp_id)} へのログイン（alice/alice, bob/bob）</p>{error}
<form method="post">
  <input type="hidden" name="SAMLRequest" value="{html.escape(saml_request)}">
  <input name="username" placeholder="username" autofocus>
  <input name="password" type="password" placeholder="password">
  <button>ログイン</button>
  <button name="cancel" value="1">キャンセル</button>
</form>"""

    assertion = s.build_assertion(ISSUER, username, sp_id, acs, req_id, user[1])
    return post_form(s.build_response(s.sign_assertion(priv, assertion), acs, req_id, issuer=ISSUER), acs)


if __name__ == "__main__":
    app.run(port=5000)
