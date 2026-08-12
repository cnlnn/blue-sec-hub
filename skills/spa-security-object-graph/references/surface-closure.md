# SPA Surface Closure Contract

本文件定义功能、路由、资源、API、身份和浏览器运行时覆盖的完整结算规则。

1. 功能点、路由和 API 分开采集，以源码、DOM、路由定义和运行时请求关联；任一单一来源不能代表完整攻击面。
2. HTML、bootstrap、主 bundle、lazy chunk、manifest、source map 和运行时资源逐项记录成功、失败或拒绝。只有强资源证据可进入下载队列，普通 `.js` 业务字符串不得当成资源。
3. 只有完成导航并确认渲染的页面计入 `pagesVisited`。超时、异常、`404/410`、登录跳转、空白页和 fallback 单列。保留 hash fragment，控件即使未点击也必须入清单，且不得采集输入值。
4. API 只从绝对 URL、同源根路径、已观测 baseURL/proxy 或运行时请求解析。相对字符串、拼接表达式、跨域地址和残片保留为 rejected/unresolved，不猜测拼接。
5. `validApis` 只统计真实浏览器请求或安全只读探测得到的 reachable/recognized 响应。假 `200`、fallback 和真实 `404/410` 排除；`401/403` 只确认边界存在。
6. 写方法和有副作用语义的 GET 不盲探。只有已捕获正常请求，或使用自有对象、最小扰动并完成清理的验证，才能升级状态。
7. 身份、角色、租户、业务状态、功能开关和服务端菜单都是覆盖维度。无法自动确认的维度保留为完成阻塞项。
8. 资产队列、资源/导航失败、路由阶段、控件、API 或身份状态任一未闭合时，`assessmentState=interim`。
9. CORS 只对精确反射保留域 Origin 的响应生成候选；凭据型候选还需验证 Cookie 实际携带、响应可读和业务影响。

静态能力、危险配置或 sink 不能自动确认漏洞。Electron 必须闭合 attacker source、renderer input、script sink、preload/IPC bridge、main consumer 和受控 OS impact。
