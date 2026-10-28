# mailapi — Cloudflare 多用戶收信系統


基於 Cloudflare Workers + D1 + R2 + Durable Objects + Email Routing。

## 功能
- API 註冊／登入，每位用戶得 `username@域名`，可加開子信箱（可設 1 小時至 30 日自動過期）
- **多域名**：管理員可加入多個收信域名
- 收信自動儲存、**自動抽取驗證碼**、**附件存 R2**（可下載／圖片預覽）
- **即時推送**：WebSocket（Durable Objects），網頁即時出信兼桌面通知
- **Webhook**：新信 POST JSON，帶 HMAC-SHA256 簽名
- **Telegram 通知**：用自己嘅 bot 即時推送驗證碼
- **規則**：轉寄、黑名單（拒收）、白名單（只收），支援關鍵字或 /正則/
- **搜尋**（FTS5 trigram，支援中文）、**星標**、**標籤**、**已讀／未讀**；星標信唔會被定期清理
- **發信／回覆**（經 Resend，需管理員開放）
- **2FA（TOTP）**、登入失敗 5 次鎖 15 分鐘
- 管理後台：用戶管理、域名、發信設定、**操作日誌**、**用量統計圖表**
- 每小時 cron 清理過期郵件同過期信箱

## 部署
1. `npm install`
2. 修改 `wrangler.toml`：`account_id`、`routes`、`MAIL_DOMAIN`、D1 `database_id`、R2 bucket
3. `npx wrangler d1 create cf-mail-db`、`npx wrangler r2 bucket create cf-mail-attachments`
4. `npx wrangler d1 execute cf-mail-db --remote --file schema.sql`（舊版升級用 `migrate_admin.sql`、`migrate_v2.sql`）
5. （可選發信）`npx wrangler secret put RESEND_API_KEY`
6. `npx wrangler deploy`
7. Cloudflare Email Routing 啟用 catch-all → 此 Worker

## 環境變數
| 變數 | 說明 |
|---|---|
| `MAIL_DOMAIN` | 預設收信域名 |
| `ALLOW_REGISTER` | 是否開放註冊（可喺後台改） |
| `RETENTION_DAYS` | 未加星標郵件保留日數 |
| `MAX_MAILBOXES` | 每用戶信箱上限 |
| `RESEND_API_KEY` | （secret，可選）發信用 |

## API
認證：`Authorization: Bearer <api_key>`。完整文件見部署後嘅 `/docs`。

支持:[![DartNode Logo](https://dartnode.com/assets/dash/images/brand/logo.png)](https://dartnode.com/)

