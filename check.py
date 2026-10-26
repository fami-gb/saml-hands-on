"""python3 check.py で実行する。最初に失敗したステップで止まり、そこが次に書く場所になる。"""
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
    a = '<a y="2" x="1">  <b>hi</b>  </a>'
    b = '<a x="1" y="2"><b>hi</b></a>'
    assert s.c14n(a) == s.c14n(b), "属性順・空白が違うだけのXMLが一致しない"
    assert s.c14n(a) != s.c14n(b.replace("hi", "HI")), "中身が違うのに一致してしまう"


def step3():
    priv, pub = s.generate_keypair()
    xml = s.build_assertion("idp", "alice", "sp", "http://sp/acs", "_req1", {"mail": "a@x"})
    signed = s.sign_assertion(priv, xml)
    assert s.verify_assertion_signature(pub, signed), "正しい署名の検証が失敗する"
    assert not s.verify_assertion_signature(pub, signed.replace(">alice<", ">admin<")), "NameID改ざんが通ってしまう"
    _, other = s.generate_keypair()
    assert not s.verify_assertion_signature(other, signed), "別の鍵で通ってしまう"


def step4():
    from datetime import datetime, timedelta, timezone
    priv, pub = s.generate_keypair()
    ACS, SP, IDP = "http://sp/acs", "sp", "idp"

    def make(**kw):
        a = dict(issuer=IDP, name_id="alice", audience=SP, recipient=ACS, in_response_to="_req1",
                 attrs={"mail": "a@x"})
        dest = kw.pop("destination", ACS)
        key = kw.pop("key", priv)
        a.update(kw)
        return s.build_response(s.sign_assertion(key, s.build_assertion(**a)), dest, a["in_response_to"])

    def verify(xml, pending=None, seen=None, **kw):
        args = dict(idp_issuer=IDP, idp_public_key=pub, sp_entity_id=SP, acs_url=ACS,
                    pending_request_ids={"_req1"} if pending is None else pending,
                    seen_assertion_ids=set() if seen is None else seen)
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

    pending, seen = {"_req1"}, set()
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
    rejected("Status失敗", make().replace(s.STATUS_OK, "urn:oasis:names:tc:SAML:2.0:status:Responder"))


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
