---
name: java-filechain-source-audit
description: 审计 Java 源码文件操作链（上传/下载/转换/预览）时用：落盘还原、后缀绕过、路径穿越、.jsp RCE 判定。
version: 1.0.0
author: hermes-curator
license: MIT
metadata:
  hermes:
    tags: [pentest, whitebox-audit, java, file-upload, path-traversal, rce]
    related_skills: [java-web-framework-pentest, cve-yu2, web-app-security]
---

# Java 文件操作链白盒审计

> 证据格式：文件:行号；置信度四级 ★★★★高 / ★★★中 / ★★低 / ★极低；每个候选给完整利用链推演（标【推演】）+ 成立条件。
> 首次固化：kykms（JeecgBoot 2.4.5 二开）本地审计，2026-08-11。案例细节与证据行号见 references/java-file-chain-audit.md（路3）、references/route8-jobs-es.md（路8·定时任务/ES/异步队列）。

## 触发条件
- 审计 Java 源码中的 MultipartFile 上传、文件下载/预览、soffice/ffmpeg 转换、物理路径拼接代码
- 判定 ".jsp 落地 = RCE 是否成立"、"上传文件能否被 HTTP 直接访问/执行"、"physicalPath 是否可控"
- 目标出现 JeecgBoot 特征（/sys/getEncryptedString、excludeUrls 配置、KM 模块）且源码在手
- 顺带面：定时任务/自动扫描导入链、ES 管理接口、线程池任务队列（本技能 §6 清单）

## 五步审计骨架
1. **落盘路径还原**：uploadDir 配置键（`@ConfigurationProperties` 前缀如 `base.upload-dir`）→ todayDir = new File(uploadDir,"yyyyMMdd") 自动 mkdirs → 存储名 = `<UUID>.<getFileSuffix(用户可控原始名)>` → physicalPath = getRelativePath(dist) 入库（**带前导 / 的字符串**）
2. **后缀提取函数分析**（getFileSuffix 类 `lastIndexOf(".")`）
3. **物理路径拼接点**（getFile/getFilePath 类）与 physicalPath 可控入口（REST CRUD 是否无 @RequiresPermissions、是否 @RequestBody 任意字段 updateById）
4. **命令拼接**（ProcessBuilder(List) vs String concat + Runtime.exec/cmd /c）
5. **解析面**（Tika/POI/LibreOffice 版本 CVE）+ anon 死配置（ShiroConfig 硬编码前缀无 Controller）

## 核心坑位（跨项目可复用）
- **Java `File(parent, child)` 绝对 child 语义（最高价值）**：child 以 `/` 开头时 parent 被忽略 → 直接指文件系统根路径。`new File(uploadDir, physicalPath)` 当 physicalPath 带前导 `/`（getRelativePath 的正常产物）→ 删除/读写落在根路径而非 uploadDir；把 physicalPath 改成 `/etc/passwd` 即任意文件删/读。`new File(physicalPath)` 同理 = 按绝对路径读。
- **纯字符串前缀比较无规范化**：getRelativePath 只做 substring 前缀 equals 比较 → `uploadDir/../../etc/passwd` 字符串可通过校验；但落盘/删除类操作受 OS "中间目录必须存在"约束（单层 ../ 需中间目录真实存在），读文件类（FileInputStream）直接归一化命中——穿越读比穿越写更可靠。
- **getFileSuffix 类 lastIndexOf(".")**：后缀内结构性不可能含 "."（双点穿越后缀内不可达）；可含 `/ \` 空格 → 目录注入仅限 uploadDir 内（`a.jsp/x` → todayDir/UUID.jsp/x）；空字节/尾点无效；大小写统一 toLowerCase 无绕过收益。**真正的绕过 = 白名单配置为空时全放行**（isFileTypeSupport: DB 配置空 → return true）。
- **存储名 `<UUID>.<suffix>` 不可预测** → .jsp 精确 URL 需认证后 list 接口拿 physicalPath（仅需登录、无权限注解的 CRUD）。
- **部署形态决定 .jsp RCE**：fat jar + 内嵌 Tomcat（docker-compose `java -jar`）= 无 jasper 默认不可执行；外部 Tomcat webapps/ROOT = JspServlet 默认可执行；磁盘→URL 映射（nginx alias / addResourceHandlers）取决于 uploadDir 是否在映射内。判法（禁网）：认证后 list 看 physicalPath 前缀；上传报错 e.getMessage() 泄露路径；grep `addResourceHandlers|ResourceHandlerRegistry` 0 命中 = 无磁盘映射。
- **下载端点 `application/octet-stream` + attachment** = 原始字节流，JSP 不执行——即使后缀 .jsp。
- **ProcessBuilder(List) = 无 shell = 无命令注入**；String concat + Runtime.exec 才有注入面。soffice 类转换是**解析 RCE 面**（LibreOffice 文档类 CVE，headless 默认禁宏），匿名上传即可触发（上传→转换标志→异步执行）。
- **死代码原语记录备查**：readKmFileString（new File(physicalPath) 任意读）、transferExternalFile(content,suffix)（任意内容+后缀写盘）——无调用方也记录，接线即漏洞。
- **源码树 yml 明文生产凭据 = 资产 + 部署形态反推**：application-prod.yml 里真实 DB 凭据（Oracle/MySQL）→ 横向入口；同时反推线上用 prod 形态而非 docker 形态。`jeecg.path.webapp` 类键全库 0 消费 = 死配置。
- **anon 死配置**：ShiroConfig 硬编码 `/onlyoffice/**` anon 无 Controller = 404 死配置；`/**/*.{html,pdf,js...}` 全 anon 在存在磁盘映射时放大存储型 XSS。
- **先落盘后建库模式**：saveFile(transferTo) 先于 saveDoc（sysUser NPE）→ 匿名上传文件永久残留 = 匿名持久化写盘原语；sha256 去重报错泄露 originalName = 哈希预言机。
- **Utils 家族横向审计清单**（工具类全扫，案例见 references/kykms-route10-utils.md）：
  - **XFF/IP 工具**：无条件信任 x-forwarded-for/Proxy-Client-IP/HTTP_CLIENT_IP/X-Real-IP 等头 → 审计日志/ES 日志 sourceIp 投毒（登录即可达，必写）；判断限流维度——用户维度 Redis key（username）则 XFF 无绕限价值，别硬报；"内网信任模式"（onlyoffice 类 `getRemoteAddr().equals(siteIp)`）常整段注释/死代码（`equals("")` 恒 false），报告写明现版不可达。
  - **序列号生成器可预测性**：`前缀+yyMMddHHmmss+nextInt(90)+10` 类 = 每秒仅 90 候选 → 枚举 oracle；必查该字段是否作查询过滤条件（mapper.xml `serial_number = #{...}`）——参数化无 SQLi 但构成枚举面，叠加权限 SQL 后影响=权限范围内精确定位/枚举。
  - **Tika 输出下游去向**：解析结果 setContent → ES IndexRequest → 索引投毒/存储 XSS 二次面（前端渲染依赖）；同步解析端点（docId 可控，docDPCheck 类）＝认证后反复触发 CPU DoS；CVE-2022-30126（OOXML 日期正则 ReDoS）适用 Tika <1.28.2，1.x 系（1.24-1.26）全中。
  - **限流/计数器工具边界 bug**：while 循环 leftPop + 随后 `range().get(0)` 读头（KMRedisUtils.resetUserLimit 类）→ 记录全部过期时最后一次 pop 使 list 为空 → IndexOutOfBoundsException → 限流接口 500，正常使用即可踩中（低危 DoS 但要列）。
  - **ProcessBuilder Windows 语义细化**：`& | < >` 对 CreateProcess 是字面量（仅 cmd.exe 解释）→ 双平台均无 shell 注入；注入必须存在 `cmd /c` 或 `/bin/sh -c` 包装。sofficePath 来自 yml 静态配置=不可控 argv，别把配置键当注入点。

## 6. 定时任务/异步队列/ES 管理面清单（跨项目可复用，案例见 references/route8-jobs-es.md）

- **自动扫描导入链 = 任意文件读（配置→job→入库→下载读回）**：可写配置项（如 JobAutoScanFileBasePath）→ quartz job 扫描目录 → transferExternalFile 类移动文件入上传目录 → saveDoc 建记录 → "免审核"服务方法直接 indexDocSync 入 ES（releaseFlag=1）→ 下载端点无校验读回。审计要点：①**JeecgBoot 定时任务注册在 DB（sys_quartz_job），源码快照无 SQL/调度代码 = 注册状态本地不可证实**，报告标【中】并给在线验证法；②**job 线程通常无 Shiro principal** → `SecurityUtils.getSubject().getPrincipal().getUsername()` NPE 中止任务（saveDoc 类）——链的最大功能阻塞点，先验证再升置信度；③job 循环无 try/catch = 单文件异常中止整轮；④导入路径常**无 isFileTypeSupport 类型检查**（与上传端点不同）。
- **`File.renameTo` 返回值被忽略 + 无条件 `file.delete()`**：跨文件系统 renameTo 失败后 `file.delete()` 仍执行 → **源文件被删除** + 随后对目标文件的操作 NPE（如 `distFile.length()`）→ "任意文件读"链同时是"源文件删除"破坏面。配套坑：`sha256(不存在文件)` 返回 null **不抛异常** → 孤儿 DB 记录照写。
- **线程池 DoS 数学**：`ArrayBlockingQueue(n) + maxThreads(m)` → 第 m+n+1 个并发提交即 RejectedExecutionException（默认 AbortPolicy；RuntimeException 在调用点无 try/catch → 500）。实例：10+20=31 并发搜索请求瘫痪搜索端点。`LinkedBlockingDeque(10000)+max10000` = 10000 排队 + 最高 10000 并发 soffice 进程风暴。**逐个端点核对限流是否真挂上**（常有主端点无限流、限流只挂在旁路端点）；同步风暴变体：convertAll 类在请求线程内同步遍历全库。
- **ES 管理面**：`/KM/EsMgnt/**` 类 anon 前缀 + `putTemplate(create(false))` = **覆盖模板**（只影响未来索引：translog async / replicas=0 / max_result_window 被固化；不删已有索引）→ 报"配置完整性 + 资源消耗"，勿报"数据丢失"。
- **ES 查询注入负面判定**：类型化 QueryBuilder API（termsQuery/matchQuery/rangeQuery/prefixQuery）+ 索引名常量 → **无 DSL 注入、无跨索引读**，直接写负面结论；把时间投到授权过滤缺失（部门过滤默认关）与畸形文档检索（releaseFlag=1 的 Draft 可被检索）上。

## 产出规范
- 报告结构：部署形态判定 → ①落盘路径还原 ②后缀绕过面 ③路径穿越 ④命令拼接 ⑤解析面 ⑥集成面 → 候选清单汇总表（按 getshell 价值排序，含置信度/前提/结论）→ 证据索引
- 每个候选：【推演 N-x】完整链 + 成立条件；区分"文件落盘成立（★★★★）"与"RCE 成立（★★ 需部署条件）"
- 子代理输出契约：任务要求"final response 必须是单个 JSON 对象"时只输出该 JSON，前后零 prose、零尾随内容；validator 报 "Extra data: line N" = JSON 后有尾随数据，重发纯 JSON 单对象
