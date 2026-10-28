---
name: deployment-config-audit
description: "部署配置/凭据审计：deploy/、yml、docker-compose 暴露面与环境差异。"
version: 1.0.0
author: hermes-curator
license: CC-BY-4.0
metadata:
  hermes:
    tags: [pentest, whitebox, config-audit, credentials, docker-compose]
    related_skills: [lowcode-framework-authz-audit, whitebox-authz-matrix-audit, cve-yu2, java-filechain-source-audit]
---

# 部署配置面审计（凭据挖掘 / 暴露面 / 环境差异 / 生产漂移）

白盒审计中针对"配置层"的路由审计。审计对象 = 仓库里的部署目录 + 各环境 profile 配置 + docker-compose + 消费这些配置的 Java/Shiro/中间件客户端代码。产出：`audit/route<N>-deploy-secrets.md` 中文报告，证据 `文件:行号`，凭据打码，四级置信度（CONFIRMED/HIGH CONFIDENCE/SUSPECTED/INFO）。

## When to Use
- 任务含"部署配置审计 / 凭据全收集 / 端口暴露 / 默认口令 / excludeUrls 差异 / 生产 vs 仓库配置"等词
- 目标仓库含 `deploy/`、`docker-compose*.yml`、`src/main/resources/application-*.yml`

## 审计步骤

### S1 摸清范围（先列全，再精读）
- `search_files(target='files')`：`deploy/**`、`application*.yml`、`application*.properties`、`docker-compose*`、`Dockerfile*`、`bootstrap*.yml`
- 注意：**快照可能缺目录**（mysql/redis/nginx conf、Dockerfile、pom.xml 被镜像内置/依赖下载）→ 缺的项在报告里显式标注"不在快照"，不要当不存在
- 读 Java 消费点：ShiroConfig（anon 清单）、ElasticsearchConfig（ES 客户端）、Service 层（ES 查询/索引构造）——配置的威胁面由消费点决定

### S2 凭据挖掘（含占位符判定 + 打码规则）
- 逐文件列：`文件:行号 | 类型 | 值打码`。打码规则：**前 8 位 + 星号**；短值（root/123456）整值写出
- 覆盖类型：DB（Oracle/MySQL/PostgreSQL）、Redis、ES、OSS/MinIO AK、SMTP、短信、onlyoffice JWT、JWT 签名、druid 监控台、swagger/knife4j basic、xxl-job token、CAS
- **占位符判定**：`??`/`xxxx`/空值在多个环境文件中逐字节相同 → 是上游模板占位符，**不是脱敏**；真实 AK 有固定格式（如 24 位 base64 风格），占位符过不了 SDK 校验。报告里必须区分"占位"与"真实泄露"
- 依赖 jar 里的密钥（如 JwtUtil 在 jeecg-boot-common 依赖中）源码不可见 → 标 INFO/HIGH"需 jar 反编译确认"，并引用旁证（如 `/sys/getEncryptedString` 默认 AES key 存活 → 部署未改默认）
- 环境变量/镜像内置配置（redis.conf、nginx conf）不可见 → 按 app 侧配置（如 redis password ''）推断

### S3 服务清单与端口暴露面
- docker-compose 每个服务：镜像 tag、端口映射、环境变量、网络模式（external bridge / host）、privileged
- 暴露面判断：宿主机映射的 3306/6379/9200/9300 + root@'%' / 无口令 → 同网段任意主机可直连；云环境再推断安全组
- 形态区分：同一仓库常有两套部署模板（如 docker 形态 MySQL root/root vs 生产形态外部 Oracle）——分别列，别混

### S4 中间件攻击面
- **ES Log4Shell 触发路径**（ES <7.16.2 且 log4j<2.15 命中 CVE-2021-44228）：
  - 路径 A 直连 9200（compose 映射 + xpack 关 + network.host 0.0.0.0）→ `/_search` query_string `${jndi:ldap://...}` → ES WARN 日志 "Failed to parse query" 含原文 → JNDI。9300 无认证可伪节点入簇
  - 路径 B 经应用：用户可控搜索词（title/content/keywords）→ ES 查询 DSL / `_analyze` / 搜索记录索引（keyword 字段超长触发 MapperParsingException 日志含原值）；需登录则查 anon 注册口补齐匿名链
  - app 自身是 logback 则 app 不中招，中招的是 ES 服务端 —— 分清
- druid/actuator/knife4j 默认口令与 anon 链：`/druid/**`、`/actuator/**`、`/doc.html`、`/swagger**/**` 常在 ShiroConfig 硬编码 anon；actuator `httptrace` 泄露 Authorization/X-Access-Token（源码注释可能自认）
- context-path（如 /ky）要拼进最终 URL

### S5 环境差异对比（profile 合并坑）
- **Spring profile 合并**：`application-test.yml`/`application-docker.yml` 没写的键继承 `application.yml`（base）→ 别把"未定义"当"无"
- excludeUrls/anon 白名单逐环境列对比表：`端点 × {V1 deploy-prod, V2 base, V3 dev, V4 repo-prod, 实测}`，标出每环境独有的误放行
- ShiroConfig 拆条逻辑：`excludeUrls` 按逗号 split 后逐条 anon，**先于**硬编码清单（同 key 时 excludeUrls 生效）

### S6 生产 vs 仓库漂移推演
- 输入：黑盒实测 anon/拦截集（引用前序 route 报告）+ 仓库各版本配置
- 匹配指纹：实测放行/拦截集去匹配哪个版本（如 querySiteInfo 被拦 → 非 dev/base 版；sys/category/** 放行 → deploy-prod 版）
- 实测放行但**所有版本都没有**的端点 → 部署方手动加配；**代码里都不存在**的路径（如 `new/*`、某 Controller）→ 部署 jar 版本漂移（比快照新）
- 输出"部署方手动加配项清单"（带证据链与置信度），并串联安全影响（匿名→RCE 全链）

### S7 产出
- 报告写 `audit/route<N>-deploy-secrets.md`：中文、证据 `文件:行号`、凭据打码、四级置信度、交叉引用前序 route 报告
- 子代理任务按 OUTPUT CONTRACT 返回机器可校验 JSON（credentials_found / services_map / excludeurls_diffs / report_path）
- 纯本地审计：凭据只记录不验证，禁触网

## 坑位
- 用 `search_files` 正则搜 `password[:=]` 可能 0 命中（yml 缩进/引号）→ 直接 `read_file` 全量读 yml 最可靠
- 一个仓库可能有两份 application-prod.yml（deploy/ 一份 + module resources 一份），凭据归属别标错
- context-path 别忘：`/actuator/httptrace` 实际是 `/<ctx>/actuator/httptrace`
- 占位符 `??` 与真实凭据混排时，报告里逐条标注"占位/真实"

## 支持文件
- `references/kykms-route9-case.md` — kykms 路9 案例：ES 7.6.1 Log4Shell 触发路径实证、excludeUrls 四版本对比表、zsk 漂移推演、凭据清单
- `scripts/credential_sweep.py` — 仓库配置凭据扫描脚本（stdlib，输出 文件:行号|类型|打码值，自动标占位符）
