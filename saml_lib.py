"""SAML自作ライブラリ。TODO を上から順に埋めていく。"""
from xml.etree import ElementTree as ET

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


# ---------- Step 1: 署名の基礎 ----------

def generate_keypair():
    """RSA鍵ペアを作り (private_key, public_key) を返す。
    ヒント: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return (private_key, public_key)
    # raise NotImplementedError("Step 1: generate_keypair")


def sign(private_key, data: bytes) -> bytes:
    """data に PKCS1v15 + SHA-256 で署名する。
    ヒント: private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    """
    # sha-256でダイジェストにして、pkcs..でrsaに合うように整形する
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    # raise NotImplementedError("Step 1: sign")


def verify(public_key, data: bytes, signature: bytes) -> bool:
    """署名が正しければ True、不正なら False を返す（例外を外に出さない）。
    ヒント: public_key.verify(...) は不正なときに InvalidSignature を投げる
    """
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
    # raise NotImplementedError("Step 1: verify")


# ---------- Step 2: XMLの正規化 ----------

def c14n(xml: str) -> bytes:
    """XML文字列を正規化してバイト列で返す。
    ヒント: ET.canonicalize(xml) は str を返す → encode
    """
    # ponytail: canonicalize は C14N 2.0。自作 IdP の XML では Exclusive C14N と同じバイト列になるが、
    # 他の IdP の XML は未検証。対応するなら lxml の Exclusive C14N に替える
    return ET.canonicalize(xml).encode()
    # raise NotImplementedError("Step 2: c14n")


# ---------- Step 3: Assertionの生成と署名 ----------
import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

NS = "urn:oasis:names:tc:SAML:2.0:assertion"
DSIG = "http://www.w3.org/2000/09/xmldsig#"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
C14N_ALG = "http://www.w3.org/2001/10/xml-exc-c14n#"
SIG_ALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
DIGEST_ALG = "http://www.w3.org/2001/04/xmlenc#sha256"
ENVELOPED_ALG = DSIG + "enveloped-signature"
# SignedInfo の中に現れる順。この連載が受け付ける方式はこの組み合わせだけ
ALGORITHMS = [C14N_ALG, SIG_ALG, ENVELOPED_ALG, C14N_ALG, DIGEST_ALG]


def _t(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _x(value):
    """XML の本文や属性値に入れる値をエスケープする。"""
    return escape(str(value), {'"': "&quot;"})


def build_assertion(issuer, name_id, audience, recipient, in_response_to,
                    attrs=None, now=None, lifetime=300):
    """署名前のAssertion XML(str)を返す。IDは "_" + secrets.token_hex(20)。時刻はUTC。
    必須: Issuer / Subject(NameID, SubjectConfirmationData: Recipient, NotOnOrAfter, InResponseTo)
          / Conditions(NotBefore, NotOnOrAfter, AudienceRestriction/Audience)
          / AuthnStatement(AuthnContext) / AttributeStatement(属性があるときだけ)
    ヒント: ルート要素に xmlns="{NS}" と ID を付ける。attrs は {"mail": "a@x"} の dict。
    """
    now = now or datetime.now(timezone.utc)
    t0, t1 = _t(now), _t(now + timedelta(seconds=lifetime))
    assertion_id = "_" + secrets.token_hex(20)
    attr_xml = "".join(
        f'<Attribute Name="{_x(k)}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
        f'<AttributeValue>{_x(v)}</AttributeValue></Attribute>'
        for k, v in (attrs or {}).items()
    )
    attr_stmt = f"\n  <AttributeStatement>{attr_xml}</AttributeStatement>" if attr_xml else ""
    return f'''<Assertion xmlns="{NS}" ID="{assertion_id}" Version="2.0" IssueInstant="{t0}">
  <Issuer>{_x(issuer)}</Issuer>
  <Subject>
    <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{_x(name_id)}</NameID>
    <SubjectConfirmation Method="{BEARER}">
      <SubjectConfirmationData Recipient="{_x(recipient)}" NotOnOrAfter="{t1}" InResponseTo="{_x(in_response_to)}"/>
    </SubjectConfirmation>
  </Subject>
  <Conditions NotBefore="{t0}" NotOnOrAfter="{t1}">
    <AudienceRestriction><Audience>{_x(audience)}</Audience></AudienceRestriction>
  </Conditions>
  <AuthnStatement AuthnInstant="{t0}">
    <AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext>
  </AuthnStatement>{attr_stmt}
</Assertion>'''


def sign_assertion(private_key, assertion_xml: str) -> str:
    """Assertion に enveloped Signature を埋め込んだXML(str)を返す。
    1. c14n(assertion_xml) の SHA-256 を base64 → DigestValue
    2. SignedInfo(方式の指定、Reference URI="#<ID>"、Transforms、DigestValue を含む)を作り、c14n して sign → SignatureValue
    3. <Signature xmlns=DSIG>SignedInfo + SignatureValue</Signature> を Issuer の直後に挿入
    ヒント: 挿入は文字列の replace("</Issuer>", "</Issuer>" + sig, 1) で十分。
    """
    canonicalized_assertion = c14n(assertion_xml)
    digest_value = base64.b64encode(hashlib.sha256(canonicalized_assertion).digest()).decode()
    assertion_id = ET.fromstring(assertion_xml).get("ID")
    signed_info = (
        f'<SignedInfo xmlns="{DSIG}">'
        f'<CanonicalizationMethod Algorithm="{C14N_ALG}"/>'
        f'<SignatureMethod Algorithm="{SIG_ALG}"/>'
        f'<Reference URI="#{assertion_id}">'
        f'<Transforms><Transform Algorithm="{ENVELOPED_ALG}"/><Transform Algorithm="{C14N_ALG}"/></Transforms>'
        f'<DigestMethod Algorithm="{DIGEST_ALG}"/>'
        f'<DigestValue>{digest_value}</DigestValue>'
        f'</Reference>'
        f'</SignedInfo>'
    )
    sig_value = base64.b64encode(sign(private_key, c14n(signed_info))).decode()
    sig = (
        f'<Signature xmlns="{DSIG}">{signed_info}'
        f'<SignatureValue>{sig_value}</SignatureValue>'
        f'</Signature>'
    )
    return assertion_xml.replace("</Issuer>", "</Issuer>" + sig, 1)
    # raise NotImplementedError("Step 3: sign_assertion")


def verify_assertion_signature(public_key, signed_xml: str) -> bool:

    """署名が正しければ True。偽造・改ざんなら False。
    0. SignedInfo の方式が ALGORITHMS と同じで、Reference が1つだけで Assertion の ID を指すか。ds:Object はないか
    1. Signature 要素を取り除いたXMLを c14n → SHA-256 が SignedInfo の中の DigestValue と一致するか
    2. SignedInfo を c14n して SignatureValue を公開鍵で verify
    ヒント: ET.fromstring でパース。取り除くのは ET の remove でよい。
    注意: 再シリアライズ(ET.tostring)すると名前空間の接頭辞が変わる。c14n は ET.canonicalize(from_file/xml_data) で通す。
    注意: remove すると Signature の後ろの空白(tail)も消える。先に直前の要素の tail へ移す。
    """
    ET.register_namespace("", NS)
    root = ET.fromstring(signed_xml)
    sig = root.find(f"{{{DSIG}}}Signature")
    info = None if sig is None else sig.find(f"{{{DSIG}}}SignedInfo")

    if info is None:
        return False

    # 書かれた方式をそのまま信じず、固定の方式と同じかを確かめる
    if [e.get("Algorithm") for e in info.iter() if e.get("Algorithm")] != ALGORITHMS:
        return False

    references = info.findall(f"{{{DSIG}}}Reference")
    if len(references) != 1 or references[0].get("URI") != f'#{root.get("ID")}':
        return False

    # 署名されないデータの置き場を認めない
    if sig.find(f"{{{DSIG}}}Object") is not None:
        return False

    # ponytail: Signature は Issuer の直後にしか入らない前提。先頭の子要素に来ると検証失敗になる
    prev = list(root)[list(root).index(sig) - 1]
    prev.tail = (prev.tail or "") + (sig.tail or "")
    root.remove(sig)
    digest = base64.b64encode(hashlib.sha256(c14n(ET.tostring(root, encoding="unicode"))).digest()).decode()
    # 署名で守られているのは SignedInfo の中だけなので、DigestValue は必ずそこから読む
    digest_value = references[0].findtext(f"{{{DSIG}}}DigestValue")

    if digest != digest_value:
        return False

    ET.register_namespace("", DSIG)
    signed_info = ET.tostring(info, encoding="unicode")
    signature_value = base64.b64decode(sig.findtext(f"{{{DSIG}}}SignatureValue", ""))
    return verify(public_key, c14n(signed_info), signature_value)


# ---------- Step 4: 検証側を書く（最重要） ----------

PROTO = "urn:oasis:names:tc:SAML:2.0:protocol"
STATUS_OK = "urn:oasis:names:tc:SAML:2.0:status:Success"
STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"


class SamlError(Exception):
    """検証失敗。メッセージに「どのチェックで落ちたか」を入れる。"""


def parse_xml(xml: str):
    """信頼できない XML を読む。SAML に DTD は不要なので、実体の宣言ごと拒否する。"""
    if "<!DOCTYPE" in xml:
        raise SamlError("0. DOCTYPE を含む XML は受け付けない")
    try:
        return ET.fromstring(xml)
    except ET.ParseError as e:
        raise SamlError(f"0. XML を読めない: {e}") from e


def no_cache(response):
    """SAML のメッセージをキャッシュさせない（Flask の after_request 用）。"""
    response.headers["Cache-Control"] = "no-cache, no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def build_response(signed_assertion: str, destination, in_response_to,
                   status=STATUS_OK, now=None, issuer=None) -> str:
    """署名済みAssertionをResponseで包む（配管なので実装済み）。エラーのときは signed_assertion を空文字列にする。"""
    now = now or datetime.now(timezone.utc)
    issuer_xml = f'<Issuer xmlns="{NS}">{_x(issuer)}</Issuer>' if issuer else ""
    return (
        f'<samlp:Response xmlns:samlp="{PROTO}" ID="_{secrets.token_hex(20)}" Version="2.0" '
        f'IssueInstant="{_t(now)}" Destination="{_x(destination)}" InResponseTo="{_x(in_response_to)}">'
        f'{issuer_xml}'
        f'<samlp:Status><samlp:StatusCode Value="{_x(status)}"/></samlp:Status>'
        f'{signed_assertion}'
        f'</samlp:Response>'
    )


def verify_response(response_xml: str, *, idp_issuer, idp_public_key, sp_entity_id,
                    acs_url, pending_request_ids: set, seen_assertion_ids: dict,
                    now=None, skew=60) -> dict:
    """全チェックを通ったら {"name_id": ..., "attrs": {...}} を返す。1つでも落ちたら SamlError。
    pending_request_ids は呼び出し側が持つ set、seen_assertion_ids は {Assertion ID: 忘れてよい時刻} の dict。
    どちらも成功時にここで更新する。

    チェック順（ロードマップ Step 4）:
      1. Response の Status が Success
      2. Assertion がちょうど1つ
      3. Issuer == idp_issuer（Format は省略か entity）
      4. 署名とダイジェスト（idp_public_key で）
      5. bearer の SubjectConfirmation、評価できる条件だけか、NotBefore / NotOnOrAfter（skew 秒の時計ずれを許容）
      6. すべての AudienceRestriction に sp_entity_id がある
      7. Recipient と Response の Destination が acs_url
      8. InResponseTo が pending_request_ids にある
      9. Assertion ID が seen_assertion_ids にない
      10. Version が 2.0 で、AuthnStatement と NameID がある
      全部通ったら、要求 ID を消し、Assertion ID を期限つきで覚える（期限を過ぎた ID はここで忘れる）

    ヒント:
      - 値(NameID, 属性)は「署名を検証した Assertion 要素」からだけ読む。Response 全体から find しない。
      - 時刻は datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
      - Response から Assertion を文字列で取り出すなら、ET.tostring の前に
        ET.register_namespace("", NS) を呼ぶ（Step 3 の verify_assertion_signature と同じ事情）。
      - 失敗は assert ではなく raise SamlError("...")。python -O で消える。
    """
    now = now or datetime.now(timezone.utc)
    skew = timedelta(seconds=skew)
    root = parse_xml(response_xml)

    # 1. Status
    code = root.find(f"{{{PROTO}}}Status/{{{PROTO}}}StatusCode")
    if code is None or code.get("Value") != STATUS_OK:
        raise SamlError("1. Status が Success ではない")

    # 2. Assertion がちょうど1つ（iter で子孫すべてを数える。入れ子に隠した偽物も数に入る）
    assertions = list(root.iter(f"{{{NS}}}Assertion"))
    if len(assertions) != 1:
        raise SamlError(f"2. Assertion が {len(assertions)} 個ある")
    assertion = assertions[0]
    if root.find(f"{{{NS}}}Assertion") is not assertion:
        raise SamlError("2. Assertion が Response の直下にない")

    # 3. Issuer（どの鍵で検証するかを決めるためだけに使う。まだ信用はしない）
    issuer = assertion.find(f"{{{NS}}}Issuer")
    if issuer is None or issuer.text != idp_issuer or issuer.get("Format") not in (None, ENTITY):
        raise SamlError("3. 信頼しない Issuer")

    # 4. 署名。ここを通るまで assertion の中身は使わない
    ET.register_namespace("", NS)
    if not verify_assertion_signature(idp_public_key, ET.tostring(assertion, encoding="unicode")):
        raise SamlError("4. 署名またはダイジェストが不正")

    # ここから下は「署名を検証した assertion」からだけ値を読む
    def parse(s):
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    # 5. 有効期限
    cond = assertion.find(f"{{{NS}}}Conditions")
    # ponytail: 最初の bearer だけを見る。自分の IdP は1つしか出さない
    bearers = [c for c in assertion.findall(f"{{{NS}}}Subject/{{{NS}}}SubjectConfirmation")
               if c.get("Method") == BEARER]
    scd = bearers[0].find(f"{{{NS}}}SubjectConfirmationData") if bearers else None
    if cond is None or scd is None or scd.get("NotOnOrAfter") is None:
        raise SamlError("5. Conditions / bearer の SubjectConfirmationData がない")
    unknown = [c.tag for c in cond if c.tag != f"{{{NS}}}AudienceRestriction"]
    if unknown:
        raise SamlError(f"5. 評価できない条件がある: {unknown}")
    not_before, not_on_or_after = cond.get("NotBefore"), cond.get("NotOnOrAfter")
    if not_before and now + skew < parse(not_before):
        raise SamlError("5. NotBefore より前（まだ有効になっていない）")
    if now - skew >= parse(scd.get("NotOnOrAfter")) or (not_on_or_after and now - skew >= parse(not_on_or_after)):
        raise SamlError("5. NotOnOrAfter を過ぎている（期限切れ）")

    # 6. Audience
    restrictions = cond.findall(f"{{{NS}}}AudienceRestriction")
    if not restrictions or any(
        sp_entity_id not in [a.text for a in r.findall(f"{{{NS}}}Audience")] for r in restrictions
    ):
        raise SamlError("6. Audience が自分の SP ではない")

    # 7. Recipient（署名内）と Destination（署名外の Response 属性）
    if scd.get("Recipient") != acs_url:
        raise SamlError("7. Recipient が自分の ACS ではない")
    if root.get("Destination") != acs_url:
        raise SamlError("7. Destination が自分の ACS ではない")

    # 8. InResponseTo（自分が出したリクエストへの応答か）
    irt = scd.get("InResponseTo")
    if irt is None or irt not in pending_request_ids or root.get("InResponseTo") != irt:
        raise SamlError("8. InResponseTo が自分の出したリクエストではない")

    # 9. リプレイ
    assertion_id = assertion.get("ID")
    if assertion_id in seen_assertion_ids:
        raise SamlError("9. 使用済みの Assertion ID（リプレイ）")

    # 10. Version と必須の要素
    name_id = assertion.findtext(f"{{{NS}}}Subject/{{{NS}}}NameID")
    if root.get("Version") != "2.0" or assertion.get("Version") != "2.0":
        raise SamlError("10. 未対応の Version")
    if assertion.find(f"{{{NS}}}AuthnStatement") is None or name_id is None:
        raise SamlError("10. AuthnStatement または NameID がない")

    # 全部通ったら状態を更新（失敗時に更新すると、攻撃者がリクエストIDを潰せてしまう）
    pending_request_ids.discard(irt)
    for used_id, forget_at in list(seen_assertion_ids.items()):
        if forget_at <= now:
            del seen_assertion_ids[used_id]
    seen_assertion_ids[assertion_id] = parse(scd.get("NotOnOrAfter")) + skew  # チェック5で期限切れになる時刻

    return {
        "name_id": name_id,
        "attrs": {
            a.get("Name"): a.findtext(f"{{{NS}}}AttributeValue")
            for a in assertion.iter(f"{{{NS}}}Attribute")
        },
    }
