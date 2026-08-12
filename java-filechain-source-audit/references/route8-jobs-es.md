# kykms 路8·定时任务/ES 管理/异步队列/Redis 限流审计案例（2026-08-11，本地纯静态）

> 目标：zsk.example.edu /ky，源码 D:\tools\audit\kykms\jeecg-boot\jeecg-boot-module-KM。
> 产出：D:\tools\audit\kykms\audit\route8-jobs-es.md（含在线验证建议与全证据索引）。与路3/路4 同战役，结论已交叉引用。

## 1. 自动扫描导入链（配置→quartz job→文件入库→下载读回 = 任意文件读）

8 环证据（每环文件:行号）：
1. 配置可写且立即生效：`KmSysConfigController.java:47-138` 无权限注解 + `edit` 带 `@CacheEvict(kmSysConfig)`（:89）；`getSysConfigValue` 为 `@Cacheable`（`KmSysConfigServiceImpl.java:23`）。key 常量 `KMConstant.java:32` JobAutoScanFileBasePath。
2. 任务读配置：`jobs/fileScanImportJob.java:36`；:41-45 目录存在性校验；:46-59 根遍历；:63-78 子目录递归（无扩展名/数量白名单）。
3. 文件移动入库：`KmDocServiceImpl.java:258-267` importExternalFile → `KmFileServiceImpl.transferExternalFile:56-77`：`file.renameTo(dist)`（:64，**返回值被忽略**）→ `HashUtil.sha256(dist)`（:69）→ `baseMapper.insert`（:70）→ **`file.delete()`（:71）无条件执行**。
4. 建文档：`KmDocServiceImpl.saveDoc:270-367`，status=Draft（:296,314）、releaseFlag=Off（:315）。
5. 免审核"发布"：`importExternalFile:263` → `auditDocImportedFile:1367-1376` **无状态前置检查**，直接 updateById + indexDocSync（与正常审核链 auditDoc:1338-1364 要求 WaitAudit 不同）。
6. ES 入库 releaseFlag=1：`indexDocSync:436-438` → singleExecute(ftiIndexDoc) → `ftiIndexDocBase:440-517`，`setReleaseFlag(Released)` :461/:492 → 产物 = status=Draft + releaseFlag=Released 畸形文档（"未审核即发布"，ES 检索 :1003-1006 只查 releaseFlag=1 → 草稿全文可检索）。
7. 读回：`downloadKmDoc:1644-1686` 无状态/发布/下载标志校验（权限段 `getKmDoc:1528-1544` 整段注释 + todo :1657 未实现）→ `getKmDoc:1517-1621` 流式返回；docId 经 searchDoc（标题=原文件名）或 listPassed/queryById 枚举获取。

**成立条件（链整体置信度【中】）**：
- 条件①：quartz 任务已在 DB `sys_quartz_job` 注册——**JeecgBoot 定时任务注册在 DB 表，源码快照无 SQL/调度代码时本地不可证实**（全仓库 grep fileScanImportJob 仅命中类本身）。
- 条件②：任务执行线程必须有已认证 Shiro principal，否则 `saveDoc:273-275` `SecurityUtils.getSubject().getPrincipal()` → `sysUser.getUsername()` NPE，整轮任务在第一个文件处中止（`fileScanImportJob:55/72` 无 try/catch）。JeecgBoot 默认 quartz 线程不带 Shiro 上下文——**这是链最大功能阻塞点，在线验证时先观察任务是否实际入库**。
- 条件③：目标目录与 uploadDir 同文件系统（renameTo 要求）。

**跨盘/失败时的破坏性细节（本路由独家发现）**：
- renameTo 失败（跨文件系统）但返回值被忽略 → `HashUtil.sha256(不存在文件)` 返回 null **不抛异常**（`HashUtil.java:15-20`）→ km_file 记录照写（sha256=null 孤儿记录）→ `file.delete()` **删除源文件** → 随后 `saveDoc:307-311` `baseConfig.getFile(...)` 返回 null → `distFile.length()` NPE → 任务中止。**即无论 renameTo 成败，源文件都会从扫描目录消失**（成功=移动，失败=删除+孤儿记录+NPE）。

## 2. ES 管理面（IKmEsMgntService 实现类）

- 暴露：`EsMgntController.java:18` /KM/EsMgnt，三个 PUT 端点 :25-44 直连 initKmDocTemplate/initKmDocVisitTemplate/initKmSearchRecordTemplate；**ShiroConfig.java:78 `/KM/EsMgnt/**` = anon → 未认证可调**。
- `KmEsMgntServiceImpl.java:116-167` initKmDocTemplate：`request.create(false)`（:158）→ putTemplate **覆盖同名模板**。模板只影响**未来新建**索引：settings 被固化 refresh_interval=10s、**translog.durability=async+sync_interval=120s（节点崩溃丢数据）**、shards=2、**replicas=0**、max_result_window=1000；mapping 被重置。visit/search 模板同构（:170-237，translog async 600s）。
- `initEXIndex:51-65`：写"for init"假文档再删（索引缺失时触发创建）→ 反复调用 = ES 写删抖动。
- `initTemplateAndSyncDocs:79-113`：若索引缺失 → `syncReleasedDocToES:68-76` 全量重索引已发布文档（打满 singleExecutor 队列）。
- **结论**：无 deleteIndex/deleteTemplate API → "删索引/数据丢失"不成立；真实破坏 = 未来索引可靠性配置被 anon 覆盖 + 反复调用资源消耗（P1）。在线验证勿在生产反复触发。

## 3. ES 查询构造（EsUtils.buildESQueryParams）——负面结论

- `EsUtils.java:47-57` buildESQueryParams / `:59-188` buildESQueryParam：**全部类型化 QueryBuilder API**（termsQuery/matchQuery/matchPhraseQuery/rangeQuery/prefixQuery），字段名硬编码，无 query_string、无 raw JSON、无用户可控字段名/索引名 → **无 ES DSL 注入**。index 固定常量别名（`KmDocServiceImpl.java:1055` km_doc_alias）→ **无跨索引读**。
- 真实风险面：①检索授权过滤缺失（`searchESKmDoc:983-1001` 部门过滤仅当 DepartmentFilterEnabled==1 且无 DepartmentFilterIgnore 权限，默认关）；②畸形文档（releaseFlag=1 的 Draft）可被检索；③配置值注入 ES 参数：`DuplicateCheckHitRate` 可写配置 → `minimumShouldMatch`（:1130-1142）畸形值 500；④排序字段 column 用户可控但 fieldSort 非注入。
- **教训：ES 查询注入审计先看是否 builder API + 索引名是否常量——两者成立直接写负面结论，把时间投到授权过滤缺失上。**

## 4. 线程池/异步队列 DoS（ThreadPoolExecutorService）

- `ThreadPoolExecutorService.java:17-22`：singleExecutor = core1/max10000/LinkedBlockingDeque(10000)；poolExecutor = core5/max20/**ArrayBlockingQueue(10)**；拒绝策略默认 AbortPolicy。
- **队列拒绝数学**：ArrayBlockingQueue(n) + max(m) → 第 m+n+1 个并发提交即 RejectedExecutionException（RuntimeException，调用点无 try/catch → 500）。本例 poolExecutor 10+20 → **约 31 并发 POST /KM/kmDoc/searchDoc 即搜索功能瘫痪**。
- 提交点：`KmDocServiceImpl.java:1091` logSearch（内部**同步**调 ES analyze `KmSearchRecordServiceImpl.java:76` + DB save + ES index，单任务耗时可观）；`KmDocVisitRecordServiceImpl.java:94,100,102` logVisit 三连 submit。
- singleExecutor 放大面：`saveDoc:363-365` 上传可转换文件 → convertDocSync（每任务起 soffice 子进程 `OfficeUtils.java:79-123` ProcessBuilder）→ 10000 排队 + 最高 10000 并发进程 = 主机资源耗尽（上传 sha256 去重 `KmDocController.java:79-82` 需不同内容文件）。
- **同步风暴变体**：`KmDocController.java:798-813` convertAll 在**请求线程内同步**遍历全库非 pdf 文档逐个转换（不走 executor）——单请求数小时占用 Tomcat 线程。
- **限流挂载检查**：主检索 searchDoc→searchESKmDoc（:839-1097）**根本没挂 validUserLimit**——UserSearchLimitPrefix 只保护 checkDuplicateESKmDoc:1109。审计时逐个端点核对限流是否真挂上。

## 5. KMRedisUtils 限流缺陷（全方法）

- key 构造 = 固定前缀常量 + username 拼接（`KMRedisUtils.java:35,47,80`，前缀 `KMConstant.java:16-19` 均以 _ 结尾）→ **无伪造面、无会话固定面（绑定用户不绑会话/IP）【高】**。
- 绕过链：①阈值来自可写配置 `KMConstant.java:73-93`（downloadLimitConfig/searchLimitConfig/viewLimitConfig）→ 改大即绕过；②每用户计数 → 多账号 N×（/sys/user/register anon `ShiroConfig.java:93`）；③check-then-act 非原子（validUserLimit:28-38 与 refreshUserLimit:74-87 分离）TOCTOU。
- **窗口边界崩溃 bug（高价值）**：`resetUserLimit:54-69` while 循环末次 `leftPop` 后列表为空时 `range(userKey,0,1).get(0)`（:57-59,63-68）对空列表取下标 0 → IndexOutOfBoundsException → 调用点（`KmDocServiceImpl.java:1664,1704` 无 try/catch；:1109 仅 catch ParseException）→ **每次限流窗口边界间歇 500 + 窗口重置**（崩溃后空列表 → 下一请求直接放行）。
- Redis 故障：validUserLimit 无降级 → Lettuce 约 60s 超时 → 下载/预览/排重检索整体 500（与路4 结论一致）。

## 6. 与其它路线衔接
- 路4（route4-logic.md）：配置写入口、EsMgnt anon、convertAll DoS 已列【中】；本路由补齐 8 环证据 + 两个新阻塞条件（Shiro principal NPE、renameTo/delete 跨盘行为）+ 队列拒绝数学。
- 报告结构沿用：结论摘要表（编号/发现/位置/置信度/等级）→ 分节证据 → 在线验证建议（勿在生产反复触发覆盖型端点）→ 证据索引 → 与前置路线衔接。
