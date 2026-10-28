---
name: patch-diff-variant-hunting
description: "从厂商安全补丁反推漏洞指纹，再横扫同类系统找变种（n-day → 0day）。给定仓库与修复提交/版本区间时使用。"
license: MIT
---
# 补丁差分 → 变种狩猎

## 何时用
- 拿到某系统的安全修复提交（GitHub PR / commit / 两个版本 tag），想找**同一根因**在别处是否还存在
- 想从别人修的洞推导出新的未公开洞（变种），而不是重复打已知 CVE

## 核心判断
**被删掉的行 = 漏洞写法指纹；新增的行 = 补的检查。**
- 拿「被删写法」去扫兄弟项目 / 二开版本 / 同厂商其他系统 → 这才是 0day 来源
- 拿「新补的检查」反推绕过：只补 `intval` 就试字符串；只补 `htmlspecialchars` 就试属性/JS 上下文；只补 `mysqli_real_escape_string` 就试宽字节/多字节截断

## 流程
```bash
# 1. 找安全修复提交（git --grep 默认 BRE，竖线不是「或」，必须拆成多个 --grep）
git log --pretty='%H %ad %s' --date=short -i --grep=fix --grep=security --grep=cve -n 30

# 2. 看 diff，标注每个 hunk 属于「加校验」还是「改写法」
git show --unified=3 <sha>

# 3. 把被删的危险写法压成规则（semgrep），横扫其它仓库
semgrep -c variant.yaml /path/to/other/project
```

## 内置信号表（判断一个 hunk 是不是安全修复）
| 类别 | 关键词 |
|---|---|
| XSS | `htmlspecialchars` `htmlentities` `esc_html` `escape_html` |
| SQL | `prepare(` `bindParam` `addslashes` `mysqli_real_escape_string` |
| 整数化 | `intval` `(int)` `parseInt` `Integer.parseInt` `cctype_digit` |
| 路径 | `basename` `realpath` `filepath.Clean` `path.normalize` |
| 上传 | `is_uploaded_file` `getimagesize` `whitelist` `allowlist` |
| 鉴权 | `is_admin` `hasRole` `@PreAuthorize` `checkPermission` |
| 命令 | `escapeshellarg` `shlex.quote` |

## 反例（什么不算变种）
- 被删的那行只是格式化/重命名 → 无指纹价值
- 兄弟项目有相同写法但**输入不可控**（参数来自常量）→ 不是洞
- 修复只是加了 WAF 规则而没改代码 → 变种可能存在，但要单独验证编码/大小写绕过

## 参考实现
本仓库配套脚本思路见 `tools/`（若未提供，按上面三步手写即可，核心是 hunk 分类 + 规则生成）。

## 常见坑
1. `git log --grep="a|b"` 在默认 BRE 下不是「或」，会 0 命中——拆成多个 `--grep`。
2. 浅克隆（`--depth 1`）没有历史，必须 `--depth 300` 以上才有补丁可看。
3. 只修了 `htmlspecialchars` 的注入点，属性上下文仍可闭合引号。
