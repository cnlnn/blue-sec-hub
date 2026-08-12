---
name: blue-mobile-app-security
description: 对 Android、iOS 和混合移动 App 做安全评估、漏洞复测与逆向分析。输入可以是 APK、AAB、IPA、源码、抓包、接口、日志、厂商报告或设备现象；用于静态分析、动态插桩、TLS Pinning 与反调试处理、平台组件/IPC、数据存储、密码协议、隐私行为以及客户端到后端 API 的攻击路径验证。
---

# Mobile App Security

以 OWASP MASVS/MASTG 为覆盖基线，但结论必须来自当前版本 App、设备行为和后端证据。

## Workflow

1. 保存原始安装包、源码、抓包和报告，记录 SHA-256、版本、包名/Bundle ID、签名、架构、渠道和测试设备。
2. 识别 Android/iOS、原生/Flutter/React Native/Unity/WebView 及主要保护方案，先做静态提取，再决定动态环境。
3. 静态分析入口、权限、导出组件、Deep Link/URL Scheme、WebView、ATS/Network Security Config、存储、密钥、密码实现、第三方 SDK、原生库和调试残留。
4. 动态验证网络行为、TLS Pinning、Root/Jailbreak/反调试、运行时密钥与存储、IPC、剪贴板、截屏、日志和隐私数据流；记录设备状态与插桩脚本。
5. 从客户端恢复接口、参数、签名/加密协议、角色和业务对象后，转 `blue-vuln-retest` 验证后端鉴权与业务逻辑。客户端隐藏、混淆或证书锁定本身不等于服务端安全控制。
6. 使用 `blue-security-knowledge` 按需检索 `mobile-security`、`android-pentesting-tricks`、`ios-pentesting-tricks`、`mobile-ssl-pinning-bypass` 及对应 Strix Web/API 方法。
7. 使用 `blue-vulnerability-patterns` 的移动端分片检查 Web/移动后端控制一致性、主体
   绑定和旧版 API；历史 App 报告只生成测试种子。
8. 用 `blue-evidence-validation` 区分静态弱信号、运行时可利用行为、服务端影响和仅限本机的风险。

## Coverage

- Android：Manifest、导出组件、Intent/Provider、PendingIntent、WebView、Keystore、Network Security Config、APK 签名和 Native/JNI。
- iOS：Info.plist、Entitlements、URL Scheme/Universal Link、ATS、Keychain、Pasteboard、Mach-O、ObjC/Swift Runtime。
- 跨平台：Flutter AOT、Hermes、IL2CPP、JS Bridge、协议还原、Pinning、RASP、隐私清单与实际数据流。

需要最新控制编号或原子测试时，查询 [OWASP MASVS/MASTG](https://mas.owasp.org/) 和 [MAS Checklist](https://mas.owasp.org/checklists/)，不从旧材料猜测编号。

## Output

输出 App 身份与哈希、静态攻击面、动态环境、已验证行为、客户端到 API 的证据链、MASVS/MASTG 映射、影响边界、清理状态和复测脚本。
