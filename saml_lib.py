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
    ヒント: ET.canonicalize(xml, strip_text=True) は str を返す → encode
    """
    return ET.canonicalize(xml, strip_text=True).encode()
    # raise NotImplementedError("Step 2: c14n")


# ---------- Step 3: Assertionの生成と署名 ----------
import base64
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

NS = "urn:oasis:names:tc:SAML:2.0:assertion"
DSIG = "http://www.w3.org/2000/09/xmldsig#"


def _t(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_assertion(issuer, name_id, audience, recipient, in_response_to,
                    attrs=None, now=None, lifetime=300):
    """署名前のAssertion XML(str)を返す。IDは "_" + uuid。時刻はUTC。
    必須: Issuer / Subject(NameID, SubjectConfirmationData: Recipient, NotOnOrAfter, InResponseTo)
          / Conditions(NotBefore, NotOnOrAfter, AudienceRestriction/Audience)
          / AuthnStatement / AttributeStatement
    ヒント: ルート要素に xmlns="{NS}" と ID を付ける。attrs は {"mail": "a@x"} の dict。
    """
    now = now or datetime.now(timezone.utc)
    t0, t1 = _t(now), _t(now + timedelta(seconds=lifetime))
    assertion_id = "_" + uuid.uuid4().hex
    attr_xml = "".join(
        f'<Attribute Name="{k}"><AttributeValue>{v}</AttributeValue></Attribute>'
        for k, v in (attrs or {}).items()
    )
    return f'''<Assertion xmlns="{NS}" ID="{assertion_id}" Version="2.0" IssueInstant="{t0}">
  <Issuer>{issuer}</Issuer>
  <Subject>
    <NameID>{name_id}</NameID>
    <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <SubjectConfirmationData Recipient="{recipient}" NotOnOrAfter="{t1}" InResponseTo="{in_response_to}"/>
    </SubjectConfirmation>
  </Subject>
  <Conditions NotBefore="{t0}" NotOnOrAfter="{t1}">
    <AudienceRestriction><Audience>{audience}</Audience></AudienceRestriction>
  </Conditions>
  <AuthnStatement AuthnInstant="{t0}"/>
  <AttributeStatement>{attr_xml}</AttributeStatement>
</Assertion>'''


def sign_assertion(private_key, assertion_xml: str) -> str:
    """Assertion に enveloped Signature を埋め込んだXML(str)を返す。
    1. c14n(assertion_xml) の SHA-256 を base64 → DigestValue
    2. SignedInfo(Reference URI="#<ID>" と DigestValue を含む)を作り、c14n して sign → SignatureValue
    3. <Signature xmlns=DSIG>SignedInfo + SignatureValue</Signature> を Issuer の直後に挿入
    ヒント: 挿入は文字列の replace("</Issuer>", "</Issuer>" + sig, 1) で十分。
    """
    canonicalized_assertion = c14n(assertion_xml)
    digest_value = base64.b64encode(hashlib.sha256(canonicalized_assertion).digest()).decode()
    assertion_id = ET.fromstring(assertion_xml).get("ID")
    signed_info = (
        f'<SignedInfo xmlns="{DSIG}">'
        f'<Reference URI="#{assertion_id}"><DigestValue>{digest_value}</DigestValue></Reference>'
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
    1. Signature 要素を取り除いたXMLを c14n → SHA-256 が DigestValue と一致するか
    2. SignedInfo を c14n して SignatureValue を公開鍵で verify
    ヒント: ET.fromstring でパース。取り除くのは ET の remove でよい。
    注意: 再シリアライズ(ET.tostring)すると名前空間の接頭辞が変わる。c14n は ET.canonicalize(from_file/xml_data) で通す。
    """
    ET.register_namespace("", NS)
    root = ET.fromstring(signed_xml)
    sig = root.find(f"{{{DSIG}}}Signature")

    if sig is None:
        return False

    root.remove(sig)
    digest = base64.b64encode(hashlib.sha256(c14n(ET.tostring(root, encoding="unicode"))).digest()).decode()
    digest_value = sig.find(f".//{{{DSIG}}}DigestValue").text

    if digest != digest_value:
        return False

    ET.register_namespace("", DSIG)
    signed_info = ET.tostring(sig.find(f"{{{DSIG}}}SignedInfo"), encoding="unicode")
    signature_value = base64.b64decode(sig.find(f"{{{DSIG}}}SignatureValue").text)
    return verify(public_key, c14n(signed_info), signature_value)


# ---------- Step 4: 検証側を書く（最重要） ----------

PROTO = "urn:oasis:names:tc:SAML:2.0:protocol"
STATUS_OK = "urn:oasis:names:tc:SAML:2.0:status:Success"


class SamlError(Exception):
    """検証失敗。メッセージに「どのチェックで落ちたか」を入れる。"""


def build_response(signed_assertion: str, destination, in_response_to,
                   status=STATUS_OK, now=None) -> str:
    """署名済みAssertionをResponseで包む（配管なので実装済み）。"""
    now = now or datetime.now(timezone.utc)
    return (
        f'<samlp:Response xmlns:samlp="{PROTO}" ID="_{uuid.uuid4().hex}" Version="2.0" '
        f'IssueInstant="{_t(now)}" Destination="{destination}" InResponseTo="{in_response_to}">'
        f'<samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status>'
        f'{signed_assertion}'
        f'</samlp:Response>'
    )


def verify_response(response_xml: str, *, idp_issuer, idp_public_key, sp_entity_id,
                    acs_url, pending_request_ids: set, seen_assertion_ids: set,
                    now=None, skew=60) -> dict:
    """全チェックを通ったら {"name_id": ..., "attrs": {...}} を返す。1つでも落ちたら SamlError。
    pending_request_ids / seen_assertion_ids は呼び出し側が持つ set。成功時にここで更新する。

    チェック順（ロードマップ Step 4）:
      1. Response の Status が Success
      2. Assertion がちょうど1つ
      3. Issuer == idp_issuer
      4. 署名とダイジェスト（idp_public_key で）
      5. NotBefore / NotOnOrAfter（skew 秒の時計ずれを許容）
      6. Audience == sp_entity_id
      7. Recipient と Response の Destination が acs_url
      8. InResponseTo が pending_request_ids にある
      9. Assertion ID が seen_assertion_ids にない → 追加

    ヒント:
      - 値(NameID, 属性)は「署名を検証した Assertion 要素」からだけ読む。Response 全体から find しない。
      - 時刻は datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
      - Response から Assertion を文字列で取り出すなら、ET.tostring の前に
        ET.register_namespace("", NS) を呼ぶ（Step 3 の verify_assertion_signature と同じ事情）。
      - 失敗は assert ではなく raise SamlError("...")。python -O で消える。
    """
    now = now or datetime.now(timezone.utc)
    skew = timedelta(seconds=skew)
    root = ET.fromstring(response_xml)

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
    if issuer is None or issuer.text != idp_issuer:
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
    scd = assertion.find(f"{{{NS}}}Subject/{{{NS}}}SubjectConfirmation/{{{NS}}}SubjectConfirmationData")
    if cond is None or scd is None:
        raise SamlError("5. Conditions / SubjectConfirmationData がない")
    if now + skew < parse(cond.get("NotBefore")):
        raise SamlError("5. NotBefore より前（まだ有効になっていない）")
    if now - skew >= parse(cond.get("NotOnOrAfter")) or now - skew >= parse(scd.get("NotOnOrAfter")):
        raise SamlError("5. NotOnOrAfter を過ぎている（期限切れ）")

    # 6. Audience
    audiences = [a.text for a in cond.iter(f"{{{NS}}}Audience")]
    if sp_entity_id not in audiences:
        raise SamlError("6. Audience が自分の SP ではない")

    # 7. Recipient（署名内）と Destination（署名外の Response 属性）
    if scd.get("Recipient") != acs_url:
        raise SamlError("7. Recipient が自分の ACS ではない")
    if root.get("Destination") != acs_url:
        raise SamlError("7. Destination が自分の ACS ではない")

    # 8. InResponseTo（自分が出したリクエストへの応答か）
    irt = scd.get("InResponseTo")
    if irt not in pending_request_ids or root.get("InResponseTo") != irt:
        raise SamlError("8. InResponseTo が自分の出したリクエストではない")

    # 9. リプレイ
    assertion_id = assertion.get("ID")
    if assertion_id in seen_assertion_ids:
        raise SamlError("9. 使用済みの Assertion ID（リプレイ）")

    # 全部通ったら状態を更新（失敗時に更新すると、攻撃者がリクエストIDを潰せてしまう）
    pending_request_ids.discard(irt)
    seen_assertion_ids.add(assertion_id)

    return {
        "name_id": assertion.find(f"{{{NS}}}Subject/{{{NS}}}NameID").text,
        "attrs": {
            a.get("Name"): a.find(f"{{{NS}}}AttributeValue").text
            for a in assertion.iter(f"{{{NS}}}Attribute")
        },
    }
