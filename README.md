# DB MCP Server

PostgreSQL コンテナに対して任意 SQL / CRUD を実行できる MCP サーバ。
Streamable HTTP トランスポート、Docker で起動。**ロール別 Bearer トークン認証**対応。

## セットアップ

### 1. 共有ネットワークを作り、db を接続

```bash
docker network create db-net
docker network connect db-net db
```

（既に接続済みなら 2回目は "endpoint with name db already exists in network db-net" で無視可）

### 2. `.env` を確認

`.env` の `DB_USER` / `DB_PASSWORD` / `DB_NAME` を実際の db に合わせて修正し、
`MCP_TOKEN_READ` / `MCP_TOKEN_WRITE` / `MCP_TOKEN_ADMIN` にトークンを設定。

トークン生成：
```bash
python -c "
import secrets
for r in ['READ','WRITE','ADMIN']:
    print(f'MCP_TOKEN_{r}={secrets.token_urlsafe(32)}')
"
```

### 3. 起動

```bash
docker compose up -d --build
docker compose logs -f
```

MCP は `http://<WSLホストIP>:8765/mcp` で待ち受けます。

## ロールと権限

3つのロールが階層構造を成します（**admin > write > read**）。上位ロールは下位ロールの権限をすべて含みます。

| ロール | 実行できるツール |
|---|---|
| **read** | `ping` / `list_schemas` / `list_tables` / `describe_table` / `select` / `execute_sql`(SELECT/EXPLAIN/SHOW/WITH...SELECT) |
| **write** | read の全て + `insert` / `update` / `delete` / `execute_sql`(INSERT/UPDATE/DELETE) |
| **admin** | write の全て + `execute_sql`(DROP/ALTER/CREATE/TRUNCATE/GRANT/REVOKE/VACUUM/REINDEX/CLUSTER) |

- リクエストの `Authorization: Bearer <token>` に載せたトークンから、サーバがロールを自動判定
- 権限不足のツール呼出は `{"ok": false, "error": "forbidden: role 'write' required, have 'read'"}` を返す（HTTP は 200）
- 認証失敗（トークン不正）は `401 Unauthorized` を返す
- `MCP_TOKEN_*` すべて空 → **認証無効モード**（起動時に警告ログ、開発用）

## Claude Code への登録

用途に応じて必要なロール分を登録します。

**参照だけ**（推奨: 大多数のユースケース）：
```bash
claude mcp add --transport http --scope user db-read \
  http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $MCP_TOKEN_READ"
```

**データ更新も行う**：
```bash
claude mcp add --transport http --scope user db-write \
  http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $MCP_TOKEN_WRITE"
```

**スキーマ変更・管理操作**（極力限定）：
```bash
claude mcp add --transport http --scope user db-admin \
  http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $MCP_TOKEN_ADMIN"
```

登録は `~/.claude.json` の user scope に保存されます。（WSL2 Docker Desktop なら `localhost` で届きます。）

**NO_PROXY** に `localhost,127.0.0.1` が入っていないと接続失敗するので注意（NRI 環境）。

## 動作確認

```bash
# initialize + tools/call ping を read トークンで叩く
python -c "
import json, urllib.request, os
TOKEN = os.environ['MCP_TOKEN_READ']
h = {'Accept':'application/json, text/event-stream',
     'Content-Type':'application/json',
     'Authorization': f'Bearer {TOKEN}'}
body = json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize',
    'params':{'protocolVersion':'2024-11-05','capabilities':{},
              'clientInfo':{'name':'t','version':'1'}}}).encode()
r = urllib.request.urlopen(urllib.request.Request(
    'http://127.0.0.1:8765/mcp', data=body, headers=h, method='POST'))
print(r.status, r.read().decode()[:200])
"
```

## 提供ツール

| ツール | 必要ロール | 用途 |
|---|---|---|
| `ping()` | read | DB 到達確認 + サーバ情報（現在の role も返却） |
| `execute_sql(sql, params)` | 動的 | SQL先頭で自動判定（SELECT=read, DML=write, DDL=admin） |
| `list_schemas()` | read | 非システムスキーマ一覧 |
| `list_tables(schema)` | read | テーブル一覧 |
| `describe_table(table)` | read | 列定義 + 主キー |
| `select(table, columns, where, order_by, limit)` | read | 安全な SELECT |
| `insert(table, values, returning)` | write | 1行 INSERT |
| `update(table, values, where)` | write | WHERE 必須の UPDATE |
| `delete(table, where)` | write | WHERE 必須の DELETE |

## 安全機構

- **ロール階層**による最小権限（read 用トークンでは書込ツール実行不可）
- `execute_sql` は複文 (`;` 区切り) を拒否
- `execute_sql` は SQL 内容によって必要ロールを動的判定
- `update` / `delete` は空 WHERE を拒否（全件更新事故防止）
- SELECT / `execute_sql` は `MAX_ROWS` で行数キャップ（LLM コンテキスト保護）
- 識別子は `_quote_ident` で英数字と `_` のみ許可 → SQL インジェクション対策
- 認証はトークン比較に `hmac.compare_digest` を使用（タイミング攻撃対策）

## 停止・再ビルド

```bash
docker compose down
docker compose up -d --build
```

## トークンをローテーションしたい

1. `.env` の該当 `MCP_TOKEN_*` を新トークンに差し替え
2. `docker compose up -d`（再ビルド不要、環境変数の変更でコンテナ再作成）
3. Claude Code の該当 MCP を再登録：
   ```bash
   claude mcp remove db-read -s user
   claude mcp add --transport http --scope user db-read \
     http://127.0.0.1:8765/mcp \
     -H "Authorization: Bearer <new-token>"
   ```
