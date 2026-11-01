"""SP（ポート5001）。uv run --with flask --with cryptography sp.py
先に IdP を起動して、curl -s http://localhost:5000/metadata -o idp_metadata.json で公開鍵を取り込んでおく。"""
import base64
import html
import json
import os
import secrets
import zlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from cryptography.hazmat.primitives import serialization
from flask import Flask, redirect, request, session

import saml_lib as s

SP_ID = "http://localhost:5001"
ACS = SP_ID + "/acs"
IDP_METADATA_FILE = Path(__file__).with_name("idp_metadata.json")

app = Flask(__name__)
app.secret_key = os.urandom(32)
# localhost のCookieはポートが違っても共有されるので、名前をIdPとかぶらないようにする
app.config["SESSION_COOKIE_NAME"] = "sp_session"
app.after_request(s.no_cache)

# ponytail: メモリ上で全ブラウザ共有。再起動で消えるので、本番は共有のストアに期限付きで保存する
seen_assertion_ids = {}


def idp_metadata():
    # 事前に取り込んだファイルだけを信じる。ログインのたびに通信で取りに行くと、
    # その経路を差し替えられる人に、信頼する公開鍵まで差し替えられてしまう
    return json.loads(IDP_METADATA_FILE.read_text())


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
    # 要求 ID はこのブラウザのセッションに結び付ける。別のブラウザの Response では照合に失敗する
    session["req_id"] = req_id
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
            pending_request_ids={session.get("req_id")},
            seen_assertion_ids=seen_assertion_ids,
        )
    # ValueError は base64、文字コード、時刻の形式が壊れているとき
    except (s.SamlError, ValueError) as e:
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
