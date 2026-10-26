"""IdP（ポート5000）。uv run --with flask --with cryptography idp.py"""
import base64
import html
import zlib
from xml.etree import ElementTree as ET

from cryptography.hazmat.primitives import serialization
from flask import Flask, abort, request

import saml_lib as s

ISSUER = "http://localhost:5000"
# SPの事前登録（entity ID → ACS URL）。応答の送り先はリクエストではなく、ここから決める
SPS = {"http://localhost:5001": "http://localhost:5001/acs"}
# ponytail: 平文パスワードの固定ユーザー。本物はハッシュ化してDBに
USERS = {
    "alice": ("alice", {"mail": "alice@example.com", "role": "admin"}),
    "bob": ("bob", {"mail": "bob@example.com", "role": "user"}),
}
# ponytail: 起動ごとに鍵が変わる。永続化と切り替えは「鍵ローテーション」の課題で
priv, pub = s.generate_keypair()

app = Flask(__name__)


@app.get("/metadata")
def metadata():
    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"entity_id": ISSUER, "sso_url": ISSUER + "/sso", "public_key": pem.decode()}


def parse_authn_request(saml_request):
    """HTTP-Redirect binding の逆: base64 → raw inflate → XML。(リクエストID, SPのID, ACS URL) を返す。"""
    # 本番では defusedxml を使う（XXE対策）
    req = ET.fromstring(zlib.decompress(base64.b64decode(saml_request), -15))
    issuer = req.find(f"{{{s.NS}}}Issuer")
    acs = SPS.get(issuer.text if issuer is not None else None)
    if acs is None:
        abort(400, "未登録のSP")
    if req.get("AssertionConsumerServiceURL") not in (None, acs):
        abort(400, "ACS URLが登録と違う")
    return req.get("ID"), issuer.text, acs


@app.route("/sso", methods=["GET", "POST"])
def sso():
    saml_request = request.values.get("SAMLRequest") or abort(400, "SAMLRequestがない")
    req_id, sp_id, acs = parse_authn_request(saml_request)

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
</form>"""

    assertion = s.build_assertion(ISSUER, username, sp_id, acs, req_id, user[1])
    response = s.build_response(s.sign_assertion(priv, assertion), acs, req_id)
    # HTTP-POST binding: ブラウザに自動送信フォームを返し、ブラウザ経由でSPのACSに届ける
    return f"""<form method="post" action="{html.escape(acs)}">
  <input type="hidden" name="SAMLResponse" value="{base64.b64encode(response.encode()).decode()}">
  <noscript><button>続ける</button></noscript>
</form><script>document.forms[0].submit()</script>"""


if __name__ == "__main__":
    app.run(port=5000)
