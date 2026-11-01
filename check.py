"""python3 check.py で実行する。最初に失敗したステップで止まり、そこが次に書く場所になる。"""
import base64
import hashlib
import re

import saml_lib as s


def step1():
    priv, pub = s.generate_keypair()
    data = b"hello saml"
    sig = s.sign(priv, data)
    assert s.verify(pub, data, sig), "正しい署名の検証が失敗する"
    assert not s.verify(pub, b"hello samL", sig), "1バイト変えても検証が通ってしまう"
    _, other_pub = s.generate_keypair()
    assert not s.verify(other_pub, data, sig), "別の鍵で検証が通ってしまう"


def step2():
    a = '<a y="2" x="1"><b/></a>'
    b = '<a x="1" y="2"><b></b></a>'
    assert s.c14n(a) == s.c14n(b), "属性順・空要素の書き方が違うだけのXMLが一致しない"
    c = '<a x="1"><b>hi</b></a>'
    assert s.c14n(c) != s.c14n(c.replace("hi", "HI")), "中身が違うのに一致してしまう"
    assert s.c14n(c) != s.c14n(c.replace("hi", " hi ")), "テキストの空白が消えている"


def resign(priv, signed, old, new):
    """SignedInfo の old を new に変えて、正しい鍵で署名し直す。"""
    info = re.search("<SignedInfo.*</SignedInfo>", signed).group()
    forged = info.replace(old, new)
    value = base64.b64encode(s.sign(priv, s.c14n(forged))).decode()
    return re.sub("<SignatureValue>.*</SignatureValue>", f"<SignatureValue>{value}</SignatureValue>",
                  signed.replace(info, forged))


def step3():
    priv, pub = s.generate_keypair()
    xml = s.build_assertion("idp", "alice", "sp", "http://sp/acs", "_req1", {"mail": "a@x"})
    assert "AuthnContextClassRef" in xml, "AuthnContext がない"
    assert "AttributeStatement" not in s.build_assertion("idp", "alice", "sp", "http://sp/acs", "_req1"), \
        "属性がないのに AttributeStatement を出している"
    signed = s.sign_assertion(priv, xml)
    assert s.verify_assertion_signature(pub, signed), "正しい署名の検証が失敗する"
    assert not s.verify_assertion_signature(pub, signed.replace(">alice<", ">admin<")), "NameID改ざんが通ってしまう"
    assert not s.verify_assertion_signature(pub, signed.replace(">alice<", "> alice <")), "NameIDの空白の改ざんが通ってしまう"
    _, other = s.generate_keypair()
    assert not s.verify_assertion_signature(other, signed), "別の鍵で通ってしまう"
    for label, old, new in [
        ("知らない署名方式", s.SIG_ALG, "urn:x"),
        ("知らないダイジェスト方式", s.DIGEST_ALG, "urn:x"),
        ("知らない正規化", s.C14N_ALG, "urn:x"),
        ("知らない Transform", s.ENVELOPED_ALG, "urn:x"),
        ("別の要素を指す Reference", 'URI="#', 'URI="#x'),
        ("2つ目の Reference", "</SignedInfo>", '<Reference URI="#x"/></SignedInfo>'),
    ]:
        assert not s.verify_assertion_signature(pub, resign(priv, signed, old, new)), f"{label} が通ってしまう"
    assert not s.verify_assertion_signature(pub, signed.replace("</Signature>", "<Object>x</Object></Signature>")), \
        "ds:Object が通ってしまう"
    digest = base64.b64encode(hashlib.sha256(s.c14n(xml.replace(">alice<", ">admin<"))).digest()).decode()
    outside = signed.replace(">alice<", ">admin<").replace("<SignedInfo", f"<DigestValue>{digest}</DigestValue><SignedInfo", 1)
    assert not s.verify_assertion_signature(pub, outside), "SignedInfo の外の DigestValue を信じている"


def step4():
    from datetime import datetime, timedelta, timezone
    priv, pub = s.generate_keypair()
    ACS, SP, IDP = "http://sp/acs", "sp", "idp"

    def make(**kw):
        a = dict(issuer=IDP, name_id="alice", audience=SP, recipient=ACS, in_response_to="_req1",
                 attrs={"mail": "a@x"})
        dest = kw.pop("destination", ACS)
        key = kw.pop("key", priv)
        edit = kw.pop("edit", lambda xml: xml)  # 署名の前に Assertion を書き換える
        a.update(kw)
        return s.build_response(s.sign_assertion(key, edit(s.build_assertion(**a))), dest, a["in_response_to"])

    def verify(xml, pending=None, seen=None, **kw):
        args = dict(idp_issuer=IDP, idp_public_key=pub, sp_entity_id=SP, acs_url=ACS,
                    pending_request_ids={"_req1"} if pending is None else pending,
                    seen_assertion_ids={} if seen is None else seen)
        args.update(kw)
        return s.verify_response(xml, **args)

    def rejected(label, xml, **kw):
        try:
            verify(xml, **kw)
        except s.SamlError:
            return
        raise AssertionError(f"{label} が通ってしまう")

    r = verify(make())
    assert r["name_id"] == "alice" and r["attrs"] == {"mail": "a@x"}, f"正常系の戻り値が違う: {r}"

    pending, seen = {"_req1"}, {}
    xml = make()
    verify(xml, pending=pending, seen=seen)
    assert not pending and len(seen) == 1, "成功時に pending / seen を更新していない"
    rejected("同じResponseの再送", xml, pending=pending, seen=seen)

    old = datetime.now(timezone.utc) - timedelta(hours=1)
    rejected("期限切れ", make(now=old))
    rejected("未来のNotBefore", make(now=datetime.now(timezone.utc) + timedelta(hours=1)))
    rejected("別SP宛て(Audience)", make(audience="other-sp"))
    rejected("別ACS宛て(Recipient)", make(recipient="http://evil/acs"))
    rejected("Destination違い", make(destination="http://evil/acs"))
    rejected("知らないInResponseTo", make(in_response_to="_unknown"))
    rejected("信頼しないIssuer", make(issuer="evil-idp"))
    rejected("攻撃者の鍵の署名", make(key=s.generate_keypair()[0]))
    rejected("NameID改ざん", make().replace(">alice<", ">admin<"))
    rejected("Status失敗", make().replace(s.STATUS_OK, s.STATUS_RESPONDER))

    rejected("bearer ではない Method", make(edit=lambda x: x.replace(s.BEARER, "urn:x")))
    rejected("評価できない条件", make(edit=lambda x: x.replace("</Conditions>", "<OneTimeUse/></Conditions>")))
    rejected("自分を含まない AudienceRestriction", make(edit=lambda x: x.replace(
        "</Conditions>", "<AudienceRestriction><Audience>other</Audience></AudienceRestriction></Conditions>")))
    rejected("AuthnStatement がない", make(edit=lambda x: re.sub("<AuthnStatement.*</AuthnStatement>", "", x, flags=re.S)))
    rejected("Issuer の Format", make(edit=lambda x: x.replace("<Issuer>", '<Issuer Format="urn:x">')))
    rejected("Assertion の Version", make(edit=lambda x: x.replace('Version="2.0"', 'Version="1.1"')))
    rejected("Response の Version", make().replace('" Version="2.0" IssueInstant', '" Version="1.1" IssueInstant', 1))
    no_irt = make(edit=lambda x: x.replace(' InResponseTo="_req1"', "")).replace(' InResponseTo="_req1"', "")
    rejected("InResponseTo なし", no_irt, pending={None})  # セッションのないブラウザでは要求 ID が None になる
    rejected("DOCTYPE", "<!DOCTYPE samlp:Response>" + make())
    rejected("読めない XML", "<a")

    r = verify(make(edit=lambda x: re.sub("<Conditions[^>]*>", "<Conditions>", x)))
    assert r["name_id"] == "alice", "Conditions の期限を省略した Assertion が通らない"

    tricky = 'a&b<c>"d'
    r = verify(make(name_id=tricky, attrs={"mail": tricky}))
    assert r == {"name_id": tricky, "attrs": {"mail": tricky}}, f"特殊文字が値として往復しない: {r}"

    seen = {"_old": datetime.now(timezone.utc) - timedelta(seconds=1)}
    verify(make(), seen=seen)
    assert "_old" not in seen and len(seen) == 1, "期限を過ぎた Assertion ID を忘れていない"


STEPS = [step1, step2, step3, step4]

if __name__ == "__main__":
    for f in STEPS:
        try:
            f()
        except NotImplementedError as e:
            print(f"⏳ {f.__name__}: 未実装 → {e}")
            break
        except AssertionError as e:
            print(f"❌ {f.__name__}: {e}")
            break
        print(f"✅ {f.__name__}")
    else:
        print("🎉 全ステップ通過")
