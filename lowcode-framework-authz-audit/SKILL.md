---
name: lowcode-framework-authz-audit
description: "审计JeecgBoot/若依类二开源码自定义模块越权/状态机/IDOR时用。含零注解根因定位、状态机三维、配置控制面。"
version: 1.0.0
author: hermes-curator
license: CC-BY-4.0
metadata:
  hermes:
    tags: [pentest, whitebox, jeecgboot, ruoyi, idor, authz, lowcode]
    related_skills: [java-web-framework-pentest, cve-yu2, hunt-idor, hunt-business-logic]
---

# 低代码平台自定义模块白盒越权审计范式

> 2026-08-11 实战固化：某低代码二开框架路4审计（业务逻辑/状态机/IDOR 矩阵）实战固化。
> 路6（2026-08-11）sys 模块认证链（注册/短信/图形验证码/登录/JwtFilter/枚举面）实锤见 `references/jeecg-boot-2.4.5-sys-auth-chain.md`，报告 `audit/route6-sys-auth.md`。
> 核心洞察：此类系统的越权是**系统性**的（框架级根因），不是单点漏洞——按下面顺序一次扫出全部。
> 关联：黑盒指纹/攻击面见 `java-web-framework-pentest`（user-owned，勿改）；通用白盒方法论见 `cve-yu2`（user-owned，勿改）。

## When to Use

- 拿到 JeecgBoot/若依类低代码二开的**源码**（或半源码），要审计自定义业务模块的越权/状态机/业务逻辑/配置面；
- 需要判定"任意已登录用户是否等于模块管理员"（零权限注解 + 过滤链仅 jwt）；
- 多路线白盒审计中的业务逻辑路线（状态机转移、IDOR 矩阵、收藏/评论/记录越权、配置读写面）。

## 0. 适用对象

JeecgBoot / 若依(RuoYi) / 各类 Java 低代码二开的**自定义业务模块**（如 KM 知识管理、OA 公文等 org.jeecg.modules.* 或 com.xxx.modules.* 模块）。低代码框架自带一套 CRUD 生成器，业务方通常只写 controller+service+entity，**从不写权限注解**——这就是系统性越权的温床。

## 1. 根因一票否决（先做这两步，命中即全模块沦陷）

1. **权限注解清点**：`grep -rln "RequiresPermissions\|RequiresRoles" <模块>/src` → **0 命中** = 该模块全部端点不设防。
2. **Shiro 过滤链**（`ShiroConfig.java`）查两点：
   - `/**` 兜底只挂 `jwt`（= 仅要求登录态，无角色/权限）→ 任何已登录低权账号 = 模块管理员；
   - 显式 `anon` 清单（常见 `/*/kmSysConfig/listAllConfig` 免登录读全量配置、`/*/EsMgnt/**` 免登录 ES 管理、`/druid/**`、`/actuator/**`）；
   - **厂商 excludeUrls 配置面**（application*.yml `jeecg.shiro.excludeUrls`，优先级高于 ShiroConfig 内联规则）：实例 `/category/**,/sys/category/**,/sys/dictItem/**,/KM/EsMgnt/**` → **整个 /sys/category 控制器匿名**（含 add/edit/delete/importExcel 写操作 + loadOne 列名 SQLi 疑点）。审计必先读部署配置（`deploy/*/config/application*.yml`）。

结论表述：**"自定义模块零权限注解 + 过滤链仅 jwt" = 所有越权的共同根因**，报告放第一节。

## 2. 固定攻击面清单（按实体 controller 逐个过）

JeecgController 标准六件套：`list / add / edit / delete / deleteBatch / queryById`（+exportXls/importExcel）：
- `queryById` → `getById(id)` 无归属校验 = 元数据 IDOR（列表走 QueryGenerator 权限，详情直读不走）；
- `edit` → `updateById(用户可控 body)` = 任意记录篡改（含改归属字段）；
- `deleteBatch` → `removeByIds(ids)` = 任意删除；
- `exportXls` → 走 QueryGenerator 权限，取决于数据规则配置。

## 3. 权限"假象"三连（看到了不等于有防护）

- `QueryGenerator.installAuthJdbc(XxxVO.class)` 生成的 `permissionSql`：**用户未配置数据规则时返回空串** → mapper XML 里 `${permissionSql}` 实际无过滤（默认部署 = 空过滤）；
- `@PermissionData(pageComponent=...)` 只是**菜单级**校验，只挂在 list 端点，不保护详情/动作端点；
- `${permissionSql}`/`${orderBy}` 是 mapper XML 字符串拼接点——一旦参数用户可控即 SQLi（查调用方是否传用户输入）。

## 4. 注释掉的防护 = 证据富矿

grep `sendError|FORBIDDEN|TODO|todo` 常直接命中：
- 被整段注释的权限检查（实例：`KmDocServiceImpl.java:1529-1544` 下载权限段全注释，只剩 `sysUser==null→401` 兜底）；
- **被注释掉的权限注解**（实例：SysUserController 全站 `//@RequiresRoles`/`//@RequiresPermissions` 注释 → 任意登录用户可 `changePassword` 任意用户 = 无旧密码/无归属校验的账户接管，`/sys/user/edit` 可改任意用户手机号）。grep 模式：`//@Requires`、`// @Requires`、`@RequiresRoles` 行首注释；
- `//todo:xxx` 未实现标记（实例：两处 `//todo:根据文档的部门访问范围控制访问权限`）。

注释块 + todo = "开发者知道要防护但没落地"的报告铁证（比推断"漏了防护"更有说服力）。

## 5. 状态机转移三维审计

每个转移（submitAudit/auditPass/auditReject/edit*/delete/convert 等）查三维，输出矩阵表：
① **操作者角色校验**（有没有？还是仅"已登录"） ② **对象归属校验**（owner/部门范围） ③ **状态前置校验**（status precondition）。

典型缺失组合（按危害排序）：
- 只查状态不查归属 → 任意用户操作任意对象（审核/编辑/删除全中）；
- 状态前置被注释 → deleteDoc 原设计仅 Draft/Reject 可删，注释后任意状态可删（还物理删源文件+ES 索引）；
- 编辑后链式自动过审 → `editAndRelease` 内部 `edit()` 后直接调 `auditDoc()` 置 Passed+入 ES，一步绕过审核；
- 畸形状态组合 → 导入链产物 `status=Draft + releaseFlag=Released`，而 ES 检索只过滤 releaseFlag → 草稿全文公开可检索可下载（状态机与检索条件不一致）。

## 6. 配置表 = 控制面（kmSysConfig 类）

- 若配置表可被任意登录用户写（无权限注解）+ `@Cacheable/@CacheEvict` 即时生效 → 控制面沦陷：关部门过滤、放大下载/预览限额、改检索参数；
- 定时任务读配置路径（如 fileScanImportJob 读 `JobAutoScanFileBasePath`）→ 指向任意目录 → 自动导入并"发布"文件 = 服务器任意文件外泄链；
- `listAllConfig` 若 anon → 未登录读全量安全参数（限流阈值、开关、路径）。
- 反向核查：`getSysConfigValue(key)` 的 key 是否用户可控（实例：全硬编码=无注入面，可写进"已排除"）。

## 7. 备份/管理端点 + Redis 限流

- `KmSysDbBackupController` 类：`/downloadById` = 任意登录用户下载全库 SQL 备份（全库外泄）；`/recover` = 覆写数据库；mysqldump 密码明文进命令行（`cmd /c mysqldump -u.. -p..`，可另报命令注入面）。
- Redis 限流可用性：`validUserLimit` 类方法无 try/catch + Lettuce 默认命令超时约 60s → Redis 故障时下载/预览链卡 60s 后 500（可用性 DoS）；`range(key,0,1).get(0)` 对空列表抛 IndexOutOfBounds（畸形数据 500）。

## 8. 输出纪律

- 证据格式：`文件:行号`（行号必须在 read_file 实际读取范围内）；
- 四级置信度：高=代码路径直接证实 / 中=依赖外部前提（数据规则未配置、Redis 行为、定时任务注册）/ 低=多条件组合 / 推测=未证实；
- 已排除项也要写明（实例：KmDocVersionController 整体注释=无回滚越权面；getSysConfigValue key 全硬编码=无 key 注入面）——排除项防后续路线重复挖；
- 多路线审计时产出落到 `<审计根>/audit/routeN-*.md`，父代理按 JSON 契约机器校验（state_machine_flaws / idor_points / report_path）。

## 9. 已知实例速查（kykms 路4 实锤，供同类目标对照）

- 任意状态文档下载/预览：权限段注释 + todo 未实现 → 知道 docId 即可拿草稿文件；
- 审核/删除/编辑全系无归属：低权账号可 auditPass 任意文档、delete 任意文档（物理删文件）；
- queryById 无 statusList 过滤 + installAuthJdbc 空 permissionSql → 任意文档元数据枚举；
- listTopicPageList mapper SQL 无 status/release 过滤 → 未发布文档枚举；
- 全库备份下载 / 配置任意写 → 全库外泄与关闭隔离。
- **sys 模块认证链（路6）**：register 存在性检查先于验证码=无码枚举；验证码 redis key=手机号明文+注册后不删=可复用；mLogin 无图形码=口令爆破面；JwtFilter 认证失败抛异常=500 全栈泄露；`;.js` 分号参数可命中 anon 后缀规则绕过 JWT（L3）。详见 `references/jeecg-boot-2.4.5-sys-auth-chain.md`（含 PoC 结构）。
