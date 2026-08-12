---
name: java-file-chain-audit
description: 审计 Java 上传/下载/删除链（.jsp RCE 判定、physicalPath 穿越）。
version: 1.0.0
author: hermes-curator
license: MIT
metadata:
  hermes:
    tags: [pentest, java, whitebox, file-upload, path-traversal, jeecgboot]
    related_skills: [java-web-framework-pentest, path-traversal-lfi]
---

# Java Web 文件操作链白盒审计（上传→落盘→读取/删除）

> 实战固化：zsk kykms（JeecgBoot 2.4.5 二开）路3 文件链深挖，全部方法经本地源码验证。会话细节与证据见 `references/kykms-route3.md`。

## When to Use

- 拿到 Java 二开源码（JeecgBoot/SpringBoot/RuoYi 系）要审计上传/下载/删除链、判定"上传能否 getshell"、找任意文件读/删原语时加载。
- 触发词：白盒审计、文件上传链、.jsp 落盘、getFileSuffix、physicalPath、convertPdf/soffice 命令拼接、uploadDoc 匿名写盘。

## 0. 工作流

1. **部署形态先定罪**（决定 .jsp 落盘 RCE 生死，最优先）
2. 还原落盘全链（配置源 → 目录 → 文件名 → DB 记录）
3. 枚举 physicalPath / 路径参数的每个 sink 与每个可控入口
4. 分析后缀提取 sink 的可达字符集（结构性快判）
5. 命令执行点二分（ProcessBuilder vs Runtime.exec）
6. 输出中文报告：每条候选带【推演】+ 成立条件 + 四级置信度（★★★★高/★★★中/★★低/★极低）+ 文件:行号证据索引

## 1. 部署形态先定罪（.jsp 落盘 RCE 成立与否的前提）

- 查 docker-compose/Dockerfile/启动脚本：`java -jar xxx.jar` = **fat jar 内嵌 Tomcat** → 无 webapps 解析目录，.jsp 落盘 ≠ RCE；外部 Tomcat WAR 部署且 uploadDir 落入 webapps 内才可执行。
- 查 yml `spring.resource.static-locations` 仅 classpath（`classpath:/static/,classpath:/public/`）= 无磁盘静态映射；grep `addResourceHandlers|ResourceHandlerRegistry|file:` 全库 0 命中 = 上传目录不可 URL 直达。
- 下载/预览端点若 `application/octet-stream` + attachment 字节流输出 = 即使读得到也不执行 JSP。
- **死亡判定三件套**（全中即 .jsp RCE 不成立，改走"认证任意文件读/删"链）：
  ① uploadDir 在 webroot/nginx alias 外 ②无静态映射 ③无 JspServlet。
- 真实判定法：登录后 list 端点看 physicalPath 前缀是否含 webapps 路径。
- 源码 dump 常无 pom.xml/build 文件 → 依赖版本只能标★低置信，别硬猜。

## 2. 落盘全链还原模板

```
Controller.upload (入口/权限)
  └─ 白名单校验 isFileTypeSupport(suffix)   ← 查是否 DB 配置，空→return true 全放行 = 真绕过点
  └─ saveFile(file)
       ├─ todayDir = new File(uploadDir, "yyyyMMdd") + mkdirs
       ├─ fileId = UUID（不可预测）
       ├─ suffix = getFileSuffix(originalFilename)   ← 唯一可控片段
       ├─ dist = new File(todayDir, fileId + "." + suffix); transferTo(dist)   ← 已写盘
       └─ physicalPath = getRelativePath(dist)（存 DB，含前导 /）
  └─ 下游业务方法（常因 sysUser NPE 抛错）
```

## 3. 后缀提取 sink（getFileSuffix 类）结构性快判

`lastIndexOf(".")` 截尾 + toLowerCase：
- **后缀内结构性不可能含 "."**（分割点即最后一个点）→ `../` 穿越、双后缀、空字节在后缀内**不可达**，别浪费时间试。
- 后缀可含 "/" 与任意非点字符 → 目录注入（`a.jsp/x` → todayDir/UUID.jsp/x 建子目录），无越界。
- 大小写：双方都 toLowerCase 时无大小写绕过面。
- 真正的"后缀绕过" = 白名单从 DB 配置读、配置为空 `return true` 全放行——这才是报告成立点。

## 4. physicalPath 存库 = 穿越放大器（Java 特有语义）

- **`new File(uploadDir, child)` 中 child 以 "/" 开头时 parent 被忽略**，直指文件系统根 → 正常代码即错位（uploadDir="/" 才正确），同时放大删除/读取面。审计 delete/read sink 必查此语义。
- 拼接点无净化（`uploadDir + "/" + relativePath` 直拼）→ 存库 physicalPath 含 `../../` 即穿越；`getRelativePath` 类前缀校验是纯字符串比较无规范化，`/up/dir/../../etc/passwd` 可通过校验。
- **可控入口枚举**（按可达性排序）：
  1. 通用 CRUD 控制器的 `PUT /xxx/edit`（@RequestBody 实体 + 无 @RequiresPermissions，仅登录）改任意行任意字段 = physicalPath 完全可控（JeecgBoot 系标配）
  2. `POST /xxx/add`（自造 id + 任意字段）
  3. 匿名上传接口（只能生成服务端路径，不能直接控 physicalPath，但可改引用关系）
  4. 服务端内部调用（不可控，标注即可）
- **标准任意文件读链**：匿名注册（/sys/user/register）→ 登录 → list 拿 id（doc 的 fileId/previewFileId 经 list/queryById 可枚举）→ edit physicalPath=../../../etc/passwd → preview/download 端点（FileInputStream 直拼无净化）穿越读 → 提取配置 DB/Redis 口令 → 横向 RCE。
- **标准任意文件删链**：同上 edit physicalPath → delete 端点（无状态/归属校验时）→ deleteKmFile 类 `new File(uploadDir, physicalPath).delete()` 穿越删（绝对 child 语义下前导 / 直指根路径文件）。

## 5. 写盘先于业务校验/异常（匿名持久化原语）

- `saveFile`（transferTo + INSERT）先执行，下游业务方法因 sysUser NPE 等抛错时文件已落盘，清理代码只在窄分支（如 `kmDoc!=null && id==null`）→ **匿名上传持久化实锤**。
- 审计盯"transferTo 与后续校验/事务的先后顺序"；NPE 路径不触发清理 = 报告高光成立点。

## 6. 命令执行 Java 二分

- `ProcessBuilder(List)` = 无 shell 无注入（参数数组化，文件名含 `$()`/`;`/空格均安全）→ 别报"命令注入"。
- `Runtime.exec("cmd /c ...")` 字符串拼接 = 仅 Windows 生效（Linux 无 cmd 直接失败）→ 目标 Linux 时此面直接标注不适用。
- LibreOffice 转换（soffice --convert-to pdf）触发面 = 匿名上传 docx/xls 即喂攻击者文件给解析器 → 命令注入无，解析 RCE 依赖具体 CVE（★低，别当主线）。

## 7. 解析器/Tika 审计点

- `BodyContentHandler(Integer.MAX_VALUE)` = 无写入上限 → zip bomb/超大文件 OOM **DoS**（需认证触发点时标注认证前置）。
- Tika OOXML XXE（CVE-2019-10088 类）依赖版本且需 OOB 外带 → ★极低。
- 无 pom 时版本区间按框架年代估（JeecgBoot 2.4.x ≈ 2021-2022 → tika 1.24-1.28），标★低置信。

## 8. ShiroConfig anon 清单速览（JeecgBoot 系）

- `/**/*.html|js|css|pdf|jpg|png|ico` 全匿名是标配 → 配合任何磁盘→URL 映射（nginx alias / 资源处理器）会放大存储型 XSS。
- `/onlyoffice/**` 类 anon 指向**不存在控制器** = 死配置（落静态资源 404）→ 报告写"残留配置"，别当攻击面。
- sha256 去重接口报错泄露 originalName = 文件存在性哈希预言机（低危信息泄露）。

## 9. 报告格式约定（本用户偏好）

- 中文，证据带 `文件:行号`，每条候选带【推演】+ 成立条件。
- 四级置信度：★★★★高 / ★★★中 / ★★低 / ★极低；默认配置下的结论与"偏离默认才成立"的条件分开写。
- 结论先行（"RCE 成立/不成立"一句话），再给证据表。
- 产出去 `D:\tools\audit\<项目>\audit\<route>-<主题>.md`。
