"""SP（ポート5001）。uv run --with flask --with cryptography sp.py"""
import base64
import html
import json
import os
import secrets
import zlib
from datetime import datetime, timezone
from urllib.parse import urlencode
from urllib.request import urlopen

from cryptography.hazmat.primitives import serialization
from flask import Flask, redirect, request, session

import saml_lib as s

SP_ID = "http://localhost:5001"
ACS = SP_ID + "/acs"
IDP_METADATA = "http://localhost:5000/metadata"

app = Flask(__name__)
app.secret_key = os.urandom(32)
# localhost のCookieはポートが違っても共有されるので、名前をIdPとかぶらないようにする
app.config["SESSION_COOKIE_NAME"] = "sp_session"
app.after_request(s.no_cache)

# ponytail: メモリ上で全ブラウザ共有。第6回で要求 ID をブラウザごとのセッションに移す
pending_request_ids, seen_assertion_ids = set(), set()


def idp_metadata():
    # ponytail: 毎回 HTTP で取得している。第6回で事前に取り込んだファイルに固定する
    with urlopen(IDP_METADATA) as r:
        return json.load(r)


@app.get("/")
def index():
    user = session.get("user")
    if not user:
        return '<h1>SP</h1><p>未ログイン</p><a href="/login">IdP でログイン</a>'
    return (f"<h1>SP</h1><p>{html.escape(user['name_id'])} としてログイン中</p>"
            f"<pre>{html.escape(json.dumps(user['attrs'], ensure_ascii=False, indent=2))}</pre>"
            '<a href="/logout">ログアウト</a>')


@app.get("/login")
def login():
    md = idp_metadata()
    req_id = "_" + secrets.token_hex(20)
    authn_request = (
        f'<samlp:AuthnRequest xmlns:samlp="{s.PROTO}" xmlns:saml="{s.NS}" ID="{req_id}" Version="2.0" '
        f'IssueInstant="{s._t(datetime.now(timezone.utc))}" Destination="{md["sso_url"]}" '
        f'AssertionConsumerServiceURL="{ACS}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
        f'<saml:Issuer>{SP_ID}</saml:Issuer>'
        f'</samlp:AuthnRequest>'
    )
    pending_request_ids.add(req_id)
    # HTTP-Redirect binding: raw deflate（zlibヘッダ2バイトとチェックサム4バイトを除く）→ base64 → URLエンコード
    saml_request = base64.b64encode(zlib.compress(authn_request.encode())[2:-4]).decode()
    return redirect(f'{md["sso_url"]}?{urlencode({"SAMLRequest": saml_request})}')


@app.post("/acs")
def acs():
    md = idp_metadata()
    try:
        response_xml = base64.b64decode(request.form["SAMLResponse"]).decode()
        user = s.verify_response(
            response_xml,
            idp_issuer=md["entity_id"],
            idp_public_key=serialization.load_pem_public_key(md["public_key"].encode()),
            sp_entity_id=SP_ID,
            acs_url=ACS,
            pending_request_ids=pending_request_ids,
            seen_assertion_ids=seen_assertion_ids,
        )
    except s.SamlError as e:
        return f"<h1>ログイン失敗</h1><p>{html.escape(str(e))}</p>", 403
    session.clear()  # セッション固定化対策: ログイン時に作り直す
    session["user"] = user
    return redirect("/")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(port=5001)
