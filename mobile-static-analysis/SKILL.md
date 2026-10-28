---
name: mobile-static-analysis
description: "APK / 微信小程序静态审计：组件面测绘、硬编码密钥、接口提取，以及「导出组件≠漏洞」的判据。拿到安装包或 wxapkg 时使用。"
license: MIT
---
# 移动端静态分析（APK / 小程序）

## 工具
| 工具 | 用途 |
|---|---|
| `apktool` | 解 `AndroidManifest.xml` 与资源 |
| `jadx` | APK → Java/Kotlin 源码 |
| `wxappUnpacker`（Node） | `.wxapkg` → JS |

```bash
java -jar apktool.jar d -f -s app.apk -o out_apktool
jadx -d out_jadx --no-res app.apk
node wuWxapkg.js -o out -d <path/to/xxx.wxapkg>
```

## 组件面（用 XML 解析器，不要用正则）
```python
import xml.etree.ElementTree as ET
NS='{http://schemas.android.com/apk/res/android}'
app=ET.parse('out_apktool/AndroidManifest.xml').getroot().find('application')
for tag in ('activity','activity-alias','receiver','service','provider'):
    for e in app.findall(tag):
        exp=e.get(NS+'exported'); fl=e.findall('intent-filter')
        if exp=='true' or fl:
            print(tag, e.get(NS+'name'), 'exported=', exp or '默认(有filter为true)')
```

## 关键判据：导出组件 ≠ 漏洞
每个 exported 组件必须读它自己的**权限校验 / 签名校验**代码才能定级。

实测反例（Aegis 2FA）：
| 候选 | 结论 | 依据 |
|---|---|---|
| `PanicResponderActivity` exported | 排除 | onCreate 先查 `pref_panic_trigger`，再 `checkTrustedSigner` 校验调用方签名 |
| `allowBackup=true` | 排除 | `backup_rules.xml` 仅含 sharedpref + 加固 json，库本身主密码派生密钥加密 |
| `otpauth` 深链 | 待验证 | 静态只能看到导入流程，需真机发 intent 验证是否弹确认 |

## 还能找什么（价值更高的部分）
- 硬编码密钥 / 接口域名 / 加密算法（`grep -rE "https?://|api[_-]?key|secret"`）
- 明文传输、证书固定缺失（找 `TrustManager`、`hostnameVerifier`、`OkHttpClient` 配置）
- WebView 风险：`setJavaScriptEnabled(true)` + `addJavascriptInterface`
- 小程序：接口清单 + 签名算法（前端可提取 ak/sk 与签名密钥 → 伪造请求绕过重放限制）

## 坑
1. GitHub release 资源名不要猜，先查 `api.github.com/repos/<o>/<r>/releases/latest` 的 `assets[].name`
2. npm 有同名空壳包，装完先看有没有 `bin`/`index.js`
3. 全局 npm 装不上：`npm config set prefix ~/.npm-global`
4. 无 KVM / 内存小 → 跑不了模拟器，动态（Frida/pinning）必须真机
