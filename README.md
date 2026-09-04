# DNS委任チェッカー

ドメインの DNS 委任チェーンをたどり、親ゾーンと子ゾーンの NS レコードおよび Glue レコードに不整合がないかを確認する Web アプリです。

## Web アプリ

公開版は次の URL から利用できます。

<https://www.on-link.jp/dnslamecheck/>

URL パラメーターで調査対象を指定することもできます。

```text
https://www.on-link.jp/dnslamecheck/?domain=example.com
```

## 機能

- 入力したドメインのゾーン頂点を、ルート DNS から順に探索
- DNS の委任チェーンを親から子へ追跡
- 親が保持する NS 情報と、子の権威サーバーが返す NS 情報を比較
- 親の Glue レコードと、NS ホスト名から解決した IP アドレスを比較
- RFC 9471 に基づき、in-domain glue、ゾーン外 NS の追加アドレス、および TC による TCP 再試行を表示
- IPv4 と IPv6 に対応
- UDP 応答が切り詰められた場合の TCP フォールバック
- EDNS に対応していない DNS サーバーへの再試行
- DNS 応答の短時間キャッシュ
- ゾーン頂点探索ログと委任追跡ログをツリー形式で表示
- CNAME、DNAME、タイムアウト、通信エラーなどを表示

## 判定結果

画面では、主に次のステータスを表示します。

| ステータス | 意味 |
| --- | --- |
| `DELEGATED` | 親サーバーから次の委任先 NS レコードを取得した |
| `SUCCESS` | 権威サーバーが応答し、委任情報が一致している |
| `LAME_DELEGATION_NOT_MATCH` | NS または IP アドレスの情報が一致していない |
| `LAME_DELEGATION_NO_ZONE` | 権威サーバーとして指定されているが、ゾーンを保持していない |
| `LAME_DELEGATION_NO_AUTHORITY_NS` | 権威応答の Authority セクションに NS レコードがない |
| `LAME_DELEGATION_NO_IP_ADDRESS` | NS ホスト名の IP アドレスを解決できない |
| `LAME_DELEGATION_TIMEOUT` | DNS サーバーから応答がない |
| `LAME_DELEGATION_MAX_DEPTH` | 委任チェーンが最大深度に達した |
| `NETWORK_ERROR` | DNS 通信または応答の解析でエラーが発生した |
| `CNAME_FOUND` | 入力名が CNAME のため、ゾーン委任の検査対象外になった |
| `DNAME_FOUND` | DNAME によりゾーン頂点を確定できなかった |

## 必要な環境

- Node.js 18 以降を推奨
- DNS サーバーへ UDP/TCP の 53 番ポートで接続できるネットワーク

## ローカルでの起動

1. 依存パッケージをインストールします。

   ```bash
   npm install
   ```

2. サーバーを起動します。

   ```bash
   node dns-lame-check.js
   ```

3. ブラウザーで次の URL を開きます。

   <http://localhost:3001/>

サーバーの待ち受けポートは `dns-lame-check.js` の `PORT` 定数で `3001` に設定されています。`package.json` には起動スクリプトが定義されていないため、上記の Node.js コマンドで直接起動します。

## 使い方

1. 「調査するドメイン名」にドメインを入力します。
2. 「解析スタート」を選択します。
3. 「DNS委任の要点」で全体の判定を確認します。
4. 「ゾーン頂点探索ログ」と「委任追跡ログ」で、各 DNS サーバーの応答と NS/Glue の比較結果を確認します。

入力値はホスト名として検証されます。`https://example.com` のような URL 形式も入力できますが、パスやクエリは調査対象には含まれません。

## API

### `POST /api/trace`

指定したドメインの DNS 委任を調査します。

リクエスト例:

```http
POST /api/trace
Content-Type: application/json

{"domain":"example.com"}
```

成功時は、ゾーン頂点探索の `zoneApexLog` と委任追跡の `traceLog` を含む JSON を返します。

```json
{
  "success": true,
  "zoneApexLog": [],
  "traceLog": []
}
```

ドメインが不正な場合は HTTP 400、サーバー内部でエラーが発生した場合は HTTP 500 を返します。

## 構成

- `index.html`: 入力画面、結果表示、ブラウザー側の API 呼び出し
- `dns-lame-check.js`: Express サーバー、DNS 問い合わせ、委任追跡、API
- `package.json`: Node.js の依存パッケージと ES Modules 設定
- `public/`: Express が静的配信するファイル置き場

## 注意事項

- DNS 問い合わせは、アプリケーションサーバーから各 DNS サーバーへ実行されます。利用者の端末から直接 DNS 問い合わせを行う仕組みではありません。
- 1 回の問い合わせは最大 120 秒でタイムアウトします。個々の DNS 通信のタイムアウトは 5 秒です。
- DNS サーバーの応答、ネットワーク環境、委任設定によっては、正しい設定でも通信エラーやタイムアウトになる場合があります。
- 調査対象のドメインや DNS サーバーに対する問い合わせが、運用上許可されていることを確認して利用してください。
