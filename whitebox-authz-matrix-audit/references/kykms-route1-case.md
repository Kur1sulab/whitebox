# 案例：kykms 鉴权矩阵审计（route1）

> 2026-08-11 白盒审计小北知识库 kykms（Github mahonelau/-kykms @8f130c2d），目标 zsk.example.edu（JeecgBoot，/ky context）。13 Controller / 114 端点 / 0 个 @RequiresPermissions / 5 个匿名写 0day 候选。产出 `audit/route1-authz-matrix.md`。

## 审计输入

- 源码：`D:\tools\audit\kykms\jeecg-boot\jeecg-boot-module-KM\src\main\java\org\jeecg\modules\KM\controller\`（13 个 Controller）
- 黑盒 anon 清单（父代理实测，引用标注来源）：放行 `/KM/kmDoc/{downloadKmDoc,previewKmDoc,changePreviewFile,uploadDoc}`、`/KM/kmDoc/new/*`、`/KM/EsMgnt/**`、`/km/kmKnowledgeMap/notoken/*`、`/sys/category/loadTreeRoot`、`/sys/dictItem/list`；拦截（JwtFilter 500 token 空）`/KM/kmSysDbBackup/**`、`/KM/kmSysConfig/querySiteInfo`、`/KM/HomePage/getCharData`
- 纯本地审计，未对目标发请求

## 鉴权基础设施证据（报告 §0）

| 证据 | 位置 |
|---|---|
| 默认链 `/**` → jwt | `jeecg-boot/jeecg-boot-base/jeecg-boot-base-core/src/main/java/org/jeecg/config/shiro/ShiroConfig.java:156` |
| 硬编码 anon：`/KM/kmSysConfig/listAllConfig` | `ShiroConfig.java:74` |
| 硬编码 anon：`/KM/EsMgnt/**` | `ShiroConfig.java:78` |
| 部署 excludeUrls：`/category/**,/sys/category/**,/sys/dictItem/**,/KM/EsMgnt/**` | `deploy/kykms/config/application-prod.yml:155` |
| 全目录 0 个 @RequiresPermissions；@PermissionData 仅 2 处 | KmDocController.java:271(listWaitAudit)/:296(listPassed) |

## 兜底点分布（Controller 层仅 4 处 + Service 层 2 处）

- Controller 判空：KmDocController.java:247(listDraft)/:460(auditPassBatch)、KmDocFavouriteController.java:50(list)、KmDocVisitRecordController.java:47(recentlyVisitDocs)
- Service 判空（**控制器裸奔但 service 401**）：KmDocServiceImpl.java:1652-1656(downloadKmDoc)、:1697-1701(viewKmDoc)
- Service 无判空（NPE 风险）：KmDocServiceImpl.java:271-275(saveDoc 取 principal 直接 getUsername)；KmFileServiceImpl.java:32-41(saveFile 无 principal 检查)

## 5 个匿名写 0day 候选（P0）

1. **POST /KM/kmDoc/uploadDoc**：实测 anon，无兜底。saveFile 先落盘（KmFileServiceImpl.java:32-41）→ saveDoc NPE（KmDocServiceImpl.java:273-275）→ 异常被控制器 catch（KmDocController.java:121-124）→ 文件残留 = 匿名无限写盘/存储 DoS
2. **POST /KM/kmDoc/changePreviewFile**：实测 anon，无兜底。按 docId 取文档→saveFile→updateById 改 previewFileId（KmDocController.java:732-760）= 匿名篡改预览+写盘
3-5. **PUT /KM/EsMgnt/init{KmDoc,KmDocVisit,KmSearchRecord}Template**：配置 anon 双证。PutIndexTemplateRequest create(false) 允许覆盖（KmEsMgntServiceImpl.java:158/193/228）= 匿名篡改 ES 索引模板

## 假 anon（别误报）

- GET /KM/kmDoc/downloadKmDoc、previewKmDoc：Shiro 放行但 service 层 sysUser==null→401 → 快照下不可匿名直读；黑盒"放行"仅指过滤器放行。若目标实例 service 版本不同则失效，需实测确认 401

## 版本漂移（关键教训）

- 黑盒放行的 4 个 kmDoc 端点 + `/KM/kmDoc/new/*` + `/km/kmKnowledgeMap/notoken/*` **均不在本地 ShiroConfig 白名单**，且本地无 kmDoc/new 与 kmKnowledgeMap 源码 → 目标实例 anon 面比快照宽 → 其余"被JWT拦"端点判定对目标可能失效 → 报告标注"需逐点无 token 黑盒复核"

## 任意登录用户高危链（P2，无 perms 注解）

- KmSysDbBackupController：add=mysqldump Runtime.exec（:80-127，L99 拼命令）；downloadById=任意文件下载 filePath 无校验（:137-189，L144/152-167）；delete=任意文件删除（:199-212，L206-208）；recover=整库恢复（:254-298，L277）
- 类字段注入 DB 明文凭据 @Value（:41-46）→ 配合 KmSysConfigController 配置篡改端点 = 命令注入升级面

## 端点统计（114 总数）

KmDocController 32 / EsMgntController 3 / KmDocBusinessType 8 / KmDocComments 8（路径 `/KM/KmDocComments` 大小写敏感）/ KmDocFavourite 8 / KmDocTopicType 8 / KmDocVersion **0（整文件注释）** / KmDocVisitRecord 9 / KmFile 8 / KmHonePage 3 / KmSearchRecord 10 / KmSysConfig 10 / KmSysDbBackup 7
