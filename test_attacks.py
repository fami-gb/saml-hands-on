"""python3 test_attacks.py で実行する。各攻撃が「狙ったチェック」で拒否されることを確かめる。
verify_response のチェックを1つコメントアウトすると、対応する攻撃が ❌ になる。"""
import re
from datetime import datetime, timedelta, timezone

import saml_lib as s

IDP, SP, ACS = "idp", "sp", "http://sp/acs"
priv, pub = s.generate_keypair()


def make(key=priv, destination=ACS, **kw):
    a = dict(issuer=IDP, name_id="alice", audience=SP, recipient=ACS, in_response_to="_req1",
             attrs={"role": "user"})
    a.update(kw)
    return s.build_response(s.sign_assertion(key, s.build_assertion(**a)), destination, a["in_response_to"])


def verify(xml, pending=None, seen=None):
    return s.verify_response(xml, idp_issuer=IDP, idp_public_key=pub, sp_entity_id=SP, acs_url=ACS,
                             pending_request_ids={"_req1"} if pending is None else pending,
                             seen_assertion_ids=set() if seen is None else seen)


def strip_signature(xml):
    return re.sub(r"<ds:Signature.*?</ds:Signature>|<Signature .*?</Signature>", "", xml, flags=re.S)


def replay():
    xml, seen = make(), set()
    verify(xml, seen=seen)
    # 同じブラウザ／攻撃者が同じResponseを再送。InResponseTo のチェックだけでは
    # IdP起点SSO（InResponseToなし）を守れないので、pending を戻してリプレイ単体で確かめる
    return xml, dict(pending={"_req1"}, seen=seen)


def wrapping():
    # 署名済みの本物はそのまま残し、改ざんした偽Assertionを先頭に足す。
    # 「最初に見つかったAssertionから値を読む」実装は admin になってしまう
    real = make()
    signed = real[real.index("<Assertion"):real.index("</Assertion>") + len("</Assertion>")]
    fake = strip_signature(signed).replace(">alice<", ">admin<").replace('ID="_', 'ID="_fake')
    return real.replace(signed, fake + signed), {}


def wrapping_nested():
    # 偽を Response 直下に、本物を別要素の中に隠す。数を「直下だけ」で数えると1個に見える
    real = make()
    signed = real[real.index("<Assertion"):real.index("</Assertion>") + len("</Assertion>")]
    fake = strip_signature(signed).replace(">alice<", ">admin<")
    hidden = f'<samlp:Extensions>{signed}</samlp:Extensions>'
    return real.replace(signed, hidden + fake), {}


past = datetime.now(timezone.utc) - timedelta(hours=1)
future = datetime.now(timezone.utc) + timedelta(hours=1)

# (攻撃名, (xml, verifyへの追加引数), 落ちるべきチェック番号)
ATTACKS = [
    ("NameIDの書き換え", (make().replace(">alice<", ">admin<"), {}), "4."),
    ("属性の書き換え", (make().replace(">user<", ">admin<"), {}), "4."),
    ("Signature要素の削除", (strip_signature(make()), {}), "4."),
    ("攻撃者の鍵で署名", (make(key=s.generate_keypair()[0]), {}), "4."),
    ("期限切れ", (make(now=past), {}), "5."),
    ("未来のNotBefore", (make(now=future), {}), "5."),
    ("別SP宛て(Audience)", (make(audience="other-sp"), {}), "6."),
    ("別ACS宛て(Recipient)", (make(recipient="http://evil/acs"), {}), "7."),
    ("別ACS宛て(Destination)", (make(destination="http://evil/acs"), {}), "7."),
    ("同じResponseの再送", replay(), "9."),
    ("SPが出していないInResponseTo", (make(in_response_to="_unknown"), {}), "8."),
    ("信頼しないIssuer", (make(issuer="evil-idp"), {}), "3."),
    ("Status失敗", (make().replace(s.STATUS_OK, "urn:oasis:names:tc:SAML:2.0:status:Responder"), {}), "1."),
    ("署名ラッピング(偽を先頭に追加)", wrapping(), "2."),
    ("署名ラッピング(本物を入れ子に隠す)", wrapping_nested(), "2."),
]

if __name__ == "__main__":
    assert verify(make())["name_id"] == "alice", "正常系が通らない"
    failed = 0
    for name, (xml, kw), want in ATTACKS:
        try:
            r = verify(xml, **kw)
            print(f"❌ {name}: 通ってしまった → {r}")
            failed += 1
        except s.SamlError as e:
            ok = str(e).startswith(want)
            failed += not ok
            print(f"{'✅' if ok else '⚠️ '} {name}: {e}" + ("" if ok else f"（期待: チェック{want}）"))
    print("🎉 全攻撃を拒否" if not failed else f"{failed} 件が想定どおりに拒否されていない")
    raise SystemExit(failed)
