# saml-hands-on

SAML の IdP と SP を、SAML ライブラリを使わずに Python で自作して理解するためのリポジトリです。
ブログ連載「CSの基礎もままならないけど、SAMLを自作して理解してみる」のコードです。

> **学習用です。本番では使わないでください。** XMLDSig は簡略版で、XXE 対策(defusedxml)などもしていません。

## 必要なもの

- Python 3.11 以上
- [uv](https://docs.astral.sh/uv/)(`flask` と `cryptography` をその場で入れて実行します)

## 自分で穴を埋めながら進める

`start` タグは、`saml_lib.py` の関数がすべて `NotImplementedError` になっている穴埋め版です。

```sh
git switch -c my-work start
uv run --with cryptography check.py   # 最初に失敗したステップで止まる。そこが次に書く場所
```

`main` ブランチは完成版です。

## ファイル

| ファイル | 内容 |
| --- | --- |
| `saml_lib.py` | Assertion の生成・署名・検証 |
| `check.py` | ステップごとの確認 |
| `idp.py` | IdP(ポート 5000) |
| `sp.py` | SP(ポート 5001) |
| `test_attacks.py` | 攻撃がすべて拒否されることの確認 |

## 動かす

```sh
uv run --with flask --with cryptography idp.py   # 別ターミナルで
uv run --with flask --with cryptography sp.py
```

ブラウザで http://localhost:5001 を開き、alice / alice でログインします。

```sh
uv run --with cryptography test_attacks.py
```
