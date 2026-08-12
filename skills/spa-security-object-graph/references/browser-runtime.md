# SPA Browser Runtime Handling

本文件保存从 SKILL.md 下沉的认证与浏览器运行时处理细节，按需读取；内容与 SKILL.md
原文逐字一致。SKILL.md 中的对应条目是摘要与指针。

## Header Files

认证信息放在权限为 `0600` 的临时 Header 文件中，通过
`--header-file` 引用。采集完成后删除临时文件；Manifest 只保留字段名、脱敏
URL、哈希和不可逆的值复用证据。

删除临时 Header 文件前运行
`scripts/inspect_token_claims.py <header-file> --out <task-dir>/token-claim-summary.json`。
该产物只记录 Token 类型、claim 名称和标识/联系信息/组织/权限/会话分类，不记录
claim 值、Token、Cookie 或 Header 值；用于结算客户端 Token claim 最小化检查。

## Browser Storage State

仅重放认证 Header 不一定能恢复 SPA 登录态：前端路由守卫、菜单和 lazy chunk
可能依赖 `localStorage`、`sessionStorage` 或 Cookie。已从当前受控浏览器导出
Playwright storage state 时，使用
`--browser-storage-state <0600-temporary-json>`；Manifest 只记录是否应用、文件
哈希及 origin/Cookie 数量，不保存值。Header 能通过 API 认证但浏览器仍回到登录页、
空白页或匿名菜单时，必须标记为 `header-only-auth-incomplete`，不能把该次采集当成
登录态攻击面。采集结束后同时删除 Header 和 storage-state 临时文件。

## Runtime JSON Redaction

运行时 XHR/fetch JSON 默认只落盘字段结构、类型和数量，原始响应哈希保留在
Manifest；值仅在内存中用于对象流关联，避免把 Token、个人信息和业务数据复制到
Skill 采集目录。

## Network Guard

浏览器网络守卫允许文档、静态资源、安全方法和已识别的查询型 `POST`，其他页面触发
请求进入 `blockedRequests`，不能静默放行。动态路由参数只能来自本次运行时、自有对象
或文档，否则保留为 `routesBlockedParameters`。
