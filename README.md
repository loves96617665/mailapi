# mailapi — Cloudflare 多用戶收信系統

基於 Cloudflare Workers + D1 + Email Routing 的收信 API：

- API 註冊，每位用戶得 `username@你的域名`，可加開子信箱
- 收到郵件自動儲存，並自動抽取驗證碼
- 內置 Web UI（`/`）、API 文件（`/docs`）、管理後台（admin 用戶）
- 每日 cron 自動清理超過 `RETENTION_DAYS` 嘅郵件

## 部署

1. `npm install`
2. 修改 `wrangler.toml`：`account_id`、`routes`、`MAIL_DOMAIN`、D1 `database_id`
3. 建立 D1：`npx wrangler d1 create cf-mail-db`，再 `npx wrangler d1 execute cf-mail-db --remote --file schema.sql`
4. `npx wrangler deploy`
5. 喺 Cloudflare Email Routing 啟用 catch-all，轉發去此 Worker

## 環境變數（wrangler.toml `[vars]`）

| 變數 | 說明 |
|---|---|
| `MAIL_DOMAIN` | 收信域名 |
| `ALLOW_REGISTER` | 是否開放註冊 |
| `RETENTION_DAYS` | 郵件保留日數 |
| `MAX_MAILBOXES` | 每用戶子信箱上限 |

## API

認證：`Authorization: Bearer <api_key>`。詳見部署後嘅 `/docs`。
