---
name: whitebox-authz-matrix-audit
description: 白盒鉴权矩阵审计：枚举 Controller 端点对照 anon 白名单，产出来授权攻击面全图。触发：鉴权/未授权审计。
---

# 白盒鉴权矩阵审计（未授权攻击面全图）

> 适用：有业务模块源码（GitHub 泄露 / 厂商二开包 / 客户交付）时的**未授权访问面批量审计**。比黑盒逐端点试快一个数量级，且能发现黑盒测不到的"配置层 anon 读"端点。
> 案例模板：`references/kykms-route1-case.md`（小北知识库 kykms，13 Controller / 114 端点 / 5 个匿名写 0day 候选）。
> 前端源码缺失案例：`references/kykms-route7-frontend-case.md`（ant-design-vue-jeecg 空壳 → 后端 Controller 真源 pivot + JeecgBoot anon 白名单脚枪清单 + ES 高亮存储型 XSS 链 + 双份 application-prod.yml 秘密）。

## 触发场景

- 用户给出源码目录 + 目标实例（黑盒边界已知或未知），要求"审计鉴权/未授权/越权矩阵/匿名攻击面"
- 黑盒实测出 anon 放行清单后，需要对照源码确认"哪些端点匿名可达且函数体无兜底"（= 0day 候选）
- 需要产出一张"每个端点：方法+路径+参数+鉴权注解+兜底+匿名可达性"的全图

## 五步流程

### 1. 枚举端点（先摸全）
- 类级 `@RequestMapping` + 方法级 `@GetMapping/@PostMapping/@PutMapping/@DeleteMapping/@RequestMapping`；`grep -rn "@RequestMapping\|@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping" <controller目录>`
- **路径大小写敏感**：`/KM/KmDocComments` 与 `/KM/kmDocBusinessType` 是不同路由，别合并
- 整文件注释掉的 Controller 也要记（=0 端点，INFO 级别说明，避免误报）
- 继承的 JeecgController 基类方法（exportXls/importExcel）也算端点，且常无注解

### 2. 鉴权注解统计（一条 grep 出全目录真相）
```bash
grep -rn "RequiresPermissions\|RequiresRoles\|PermissionData\|SecurityUtils.getSubject().getPrincipal()" <controller目录>
```
- **业务模块 Controller 经常 0 个 @RequiresPermissions**（kykms 13 Controller 114 端点全目录 0 个）——鉴权完全靠过滤器链 anon 白名单 + JWT 存在性，"登录即可"是常态，不是个例
- `@PermissionData` 只做数据权限（按部门/创建人过滤），**不拦截登录**，别把它当鉴权
- 函数体 `SecurityUtils.getSubject().getPrincipal()` 判空 = 兜底点，逐条标注

### 3. anon 白名单双源核查（关键证据）
- **源码硬编码**：`ShiroConfig.java`（或 SecurityConfig）里 `filterChainDefinitionMap.put(url, "anon")` 的条目
- **部署配置**：`application-prod.yml` / `application.yml` 的 `jeecg.shiro.excludeUrls`（逗号分隔，如 `/KM/EsMgnt/**,/sys/category/**`）——**deploy 目录下的配置才是目标实例真实白名单**
- 默认链：ShiroConfig 末行 `/**` → jwt（Shiro）或 Spring Security 的 permitAll 之外的认证规则
- 产出"已确认匿名端点速查表"：配置 anon + 黑盒实测 双证 = CONFIRMED；仅配置 = HIGH CONFIDENCE（建议黑盒补测）

### 4. 分层兜底检查（必须追到 service 层）
- **控制器无兜底 ≠ 无兜底**：下载/预览类端点常把 principal 判空放在 service 实现里（`sysUser==null → 401`）
- 判定规则：grep `getPrincipal()` 全模块（controller + service/impl），逐端点确认兜底在哪层
- **"黑盒放行"只证明过滤器放行**，不代表匿名可用——service 层 401 兜底会把"任意文件下载"降级为"假 anon"，报之前必须查

### 5. 版本漂移检测 + 危险度排序产出
- **版本漂移陷阱**：黑盒实测放行的路径可能**不在本地 ShiroConfig 白名单**（部署实例 excludeUrls 更宽）→ 其余"被JWT拦"端点对目标实例同样可能失效 → 报告必须注明"需逐点无 token 黑盒复核"
- 本地快照不存在的路径（黑盒测到 `/xxx/new/*` 但源码无） = 目标独有攻击面 / 版本差异，转黑盒路由枚举，标 INFO
- 排序：**匿名写（P0）> 匿名读/配置泄露（P1）> 任意登录用户高危写（无 perms 注解，P2）> 参数校验泄露（P2）**
- "anon 可达 + 函数体无 sysUser 兜底" = 未授权 0day 候选，单独成节
- 输出契约（机器可校验 JSON）：`endpoints_total` / `anon_write_endpoints` / `top_findings` / `report_path`

## 高频漏洞模式（grep 信号 → 结论）

| grep 信号 | 结论 |
|---|---|
| `saveFile(...)` 落盘 → 后续 `getPrincipal().getUsername()` 无判空 | **匿名写盘**：文件先落盘再 NPE，异常被控制器 catch → 每次请求留一个文件 = 存储耗尽 DoS + 残留（kykms uploadDoc 实锤） |
| 上传/替换端点 anon + 无兜底 | 匿名投毒/篡改（预览替换=钓鱼面），P0 |
| `Runtime.exec("mysqldump -u...-p...")` 备份/恢复 Controller | 任意登录用户高危链：命令执行面 + `downloadById` filePath 无校验=任意文件下载 + `delete` 任意文件删除 + `recover` 整库覆盖 |
| 配置接口硬编码 anon（`/xxx/listAllConfig`） | 匿名读全量系统配置，常漏报的 P1 |
| `@Value("${...password}")` 注入到 Controller | DB 明文凭据进类字段，配合配置篡改端点 = 凭据泄露/命令注入升级面 |
| checkType/statisticsType 等无枚举校验参数 | 参数校验泄露 / 服务端文件读取侧信道 |
| `HighlightBuilder.preTags("<span style=color:red...>")` + `hit.getHighlightFields()` 原样 `setTitle/setContent` | **搜索高亮注入链（存储型 XSS）**：ES 高亮片段不转义文档原文，payload 随命中原样进 JSON 响应的 title/content；后端刻意返回 span 证明前端必按 HTML 渲染（v-html，否则 span 显示字面量）→ 文档内容=存储型 XSS。上传面匿名时链路完整（kykms uploadDoc→searchDoc 全链）。前端源码缺失时标"后端 CONFIRMED / 前端 HIGH(推断)" |

## 证据纪律（沿用 cve-yu2 反幻觉规则）

- 每个结论带 `文件相对路径:行号`；代码引用必须来自真实 read 输出
- 四级置信度：CONFIRMED（源码+黑盒双证）/ HIGH CONFIDENCE（源码单证）/ SUSPECTED（推断，如越权需看 service 归属校验）/ INFO（背景、排除项）
- 报告开头放"鉴权基础设施结论"表（默认链、白名单条目、0 perms 统计），让全矩阵判定可追溯
- 纯本地审计时明确声明"未对目标发请求"；黑盒数据引用标注来源（父代理实测）

## 已知坑

- **先验货再审计**：预期源码目录可能只有空壳——本批次 `ant-design-vue-jeecg/` 目录仅含 `docker-compose-business_web.yml`（433B），前端 0 个 .vue/.js/package.json，filelist.json 也无前端条目。动手前 `find <dir> -name "*.vue|*.java|package.json" | wc -l` + 核对清单文件，确认审计对象真实存在，避免对着空目录硬编
- **前端源码缺失 ≠ 任务报废**：API 攻击面以**后端 Controller 为真源**全量枚举（比前端 api 层更权威、含管理后台专用接口），与已知端点清单（黑盒/前台路由推导）diff 找"未被发现端点"（重点管理面：备份/恢复、配置读写、审核流、统计）；前端专属项（v-html sink、router hidden:true、localStorage token、vue.config.js sourcemap/proxy）如实标【阻断·待补审】，绝不臆造
- grep `@RequestMapping("/KM/` 时括号会炸正则（`Unmatched (`），用 `grep -F` 或转义
- 一个模块的 Controller 可能在多个包/目录（如 kmKnowledgeMap 不在 controller/ 下），先 `find <module> -name "*Controller.java"` 全量确认
- CRUD 骨架 Controller（list/add/edit/delete/deleteBatch/queryById/exportXls/importExcel）9 件套几乎必无注解——不要逐个细读，表格化批量标注即可
- **部署配置与源码配置双查**：`deploy/<svc>/config/application-prod.yml` 与 `jeecg-boot-module-<x>/src/main/resources/application-prod.yml` 可能是两份（前者脱敏 `??`，后者保留真实凭据）——秘密扫描两个都扫
