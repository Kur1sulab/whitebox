# kykms 路7·前端源码审计案例（route7-frontend）

> 批次：kykms（小北知识库，JeecgBoot 二开）白盒审计第二批·路7。完整报告：`D:\tools\audit\kykms\audit\route7-frontend.md`
> 本案例核心教训：**预期前端源码目录为空壳时如何不报废任务** + JeecgBoot 前端审计常见发现清单。

## 场景

任务：审计 `ant-design-vue-jeecg/` 前端源码（API 攻击面 / 硬编码秘密 / 隐藏路由 / XSS sink / token 处理 / sourcemap 配置）。

**验货结果**：目录仅含 `docker-compose-business_web.yml`（433B 商业镜像引用）；全机 `find -name "*.vue"` = 0；filelist.json 无前端条目。前端源码整体缺失。

## 替代取证路径（已验证有效）

1. **API 攻击面 → 后端 Controller 为真源**：`find <module> -name "*Controller.java"` + 正则枚举类级/方法级 @RequestMapping，产出全端点表（kykms：13 KM Controller 90+ 端点 + sys 快照）。
2. **与已知清单 diff**：已知（黑盒/前台路由）清单 vs 后端全量 → "未被发现端点"（重点管理后台：备份/恢复、配置读写、审核流、统计）。
3. **前端专属项如实标【阻断·待补审】**：v-html sink、router hidden:true、localStorage token key、vue.config.js productionSourceMap —— 不臆造。

## kykms 新端点（管理后台面，已知清单外）

- `/KM/kmSysDbBackup/{add,downloadById,recover,delete,deleteBatch,queryById}` —— downloadById=全库 SQL 下载；recover=整库恢复；add 触发 `cmd /c mysqldump -u.. -p<密码>`（密码上命令行）。无任何 @RequiresPermissions。
- `/KM/kmSysConfig/listAllConfig` **匿名**（ShiroConfig 硬编码 put anon）；add/edit/delete 配置读写。
- `/KM/kmDoc/{auditPass,auditPassBatch,auditReject,auditRejectBatch,submitAudit,submitAuditBatch,listWaitAudit,listPassed,convertAll,editRelease,editReleaseFlag,resetPreviewFile,docDPCheck,advanceSearchDoc,queryKmDocStatistics}`。
- `/KM/HomePage/{getCharData,listRecommendTopic,listBusinessType}`、`/KM/kmSearchRecord/{hotKeywordReport,hotTopicReport}`、`/KM/kmDocVisitRecord/recentlyVisitDocs`。
- `/sys/common/transitRESTful?url=` —— **无过滤 SSRF + 自动转发调用者 X-Access-Token**（CommonController.java:360-362）。
- sys 快照：登录面、`/sys/user/*` 40+、`/sys/annountCement/*`、`/sys/category/*`、`/sys/duplicate/check`。

## JeecgBoot anon 白名单脚枪（ShiroConfig.java 逐条看）

`/KM/kmSysConfig/listAllConfig`、`/KM/EsMgnt/**`、`/onlyoffice/**`、`/druid/**`、`/doc.html`、`/swagger**/**`、`/webjars/**`、`/v2/**`、`/jmreport/**`、`/sys/annountCement/show/**`、`/bigscreen/**`、`/websocket/**`、**`/actuator/**`**（metrics,httptrace）、**`/**/*.js.map` + `/**/*.css.map`**（sourcemap 匿名=前端源码还原面）；`/**/*.js|css|html|svg|pdf|jpg|png|ico|ttf|woff|woff2` 全 anon。

## 秘密（双份 application-prod.yml 都要扫）

- deploy 副本 `deploy/kykms/config/application-prod.yml` 大量脱敏 `??`；**module 源码副本 `jeecg-boot-module-system/src/main/resources/application-prod.yml` 保留真实值**：生产 Oracle 库 `jdbc:oracle:thin:@106.52.244.12:1521:GHYZSK` / 用户 ZSK（密码见报告，不在此记录）。
- Druid 监控台 `admin/123456` + `/druid/**` anon；knife4j `production: false` + basic `jeecg/jeecg1314` + `/doc.html` anon；MySQL root/root；Redis 无认证 / 123456。

## XSS 链（后端 CONFIRMED / 前端 HIGH 推断）

- `KmDocServiceImpl.java:1034-1035`：`preTags("<span style=color:red;font-weight:bold>")`；`:1179-1180` color:blue 变体。
- `:1067-1082`：ES 高亮片段**不转义**文档原文，原样 `setTitle/setContent` 进 JSON。
- 链：uploadDoc（匿名）→ 文档含 HTML payload → searchDoc 命中 → 原样回显 → 前端 v-html 渲染 = 存储型 XSS。后端刻意返回 span 反证前端按 HTML 渲染。

## Token 处理

- JwtFilter.java:55-58：`X-Access-Token` 头优先，**回退 `token` URL 参数**（泄露面）；:80-84 CORS 反射 Origin + Allow-Credentials:true。
- 前端存储方式（JeecgBoot 2.x 惯例 localStorage `pro__Access-Token`）无法本地取证，标 INFO。

## 输出契约

`new_endpoints_found` / `hardcoded_secrets` / `xss_sinks` / `report_path`（JSON）。
