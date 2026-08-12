---
name: mybatis-xml-sqli-audit
description: 源码审计 SQL 注入时用：枚举 MyBatis Mapper XML ${} 拼接并做污点追踪。
version: 1.0.0
author: hermes-curator
license: MIT
metadata:
  hermes:
    tags: [pentest, sqli, java, mybatis, code-audit, jeecgboot]
    related_skills: [java-web-framework-pentest, sqli-sql-injection]
---

# MyBatis Mapper XML ${} 白盒 SQLi 审计

> 2026-08-11 zsk（JeecgBoot 2.4.5 二开 kykms）route2 固化：5 个 `${}` sink 全量枚举 + 链式追踪，2 个 orderBy 注入判定为高置信度（CVE-2023-1454 类）。完整链路证据见 `references/jeecgboot-route2-chain.md`。

## When to Use（触发时机）

- 拿到 Java/Spring 二开源码 dump（JeecgBoot/RuoYi/SpringBoot+MyBatis-Plus），任务说"审计 SQL 注入/污点追踪"。
- 黑盒撞出 order by 类报错，需要源码侧定位 sink。
- 目标是查 Mapper XML `${}` 而非 `#{}`。

## 0. 先找版本（dump 常没有 pom.xml）

1. `find . -name pom.xml` 找不到时：
   - `deploy/docker-compose*.yml` 里 `command: java -jar ./jeecg-boot-module-system-<版本>.jar`（一行实锤）。
   - 代码 import 佐证：`org.jeecg.common.system.query.QueryGenerator` / `LoginUser` / `PermissionData` = JeecgBoot 2.4.x 三件套。
2. 版本→漏洞线记忆：
   - JeecgBoot **CVE-2023-1454 修复线 = 3.5.0**（2023-03 对 column/order 加列名校验），< 3.5.0 全受影响。
   - 基座框架源码（QueryGenerator、PermissionDataAspect）常不在二开 dump 里——**别因找不到源码停下**，上游是框架已知语义，按行为推。

## 1. sink 枚举（${} 全量）

```bash
grep -rn '\${' <module>/src/main/java/**/mapper/xml/
```

- 坑：search_files 的 `${` 正则要写成 `\$\{`，容易 0 结果误判"没有拼接"——**直接 terminal grep 更稳**。
- 统计特征：12 个 XML 里通常只有 2-3 个含 `${}`（复杂联表查询），其余全 `#{}` 安全。报告里要写明"其余 N 个 XML 0 个 `${}`"（排除性证据）。
- Mapper 接口的 `@Param("xxx")` 名与 XML `${xxx}` 一一对应，是追踪的锚点：接口签名里每个 @Param 就是 XML 的一个可注入变量。

## 2. 污点追踪标准链

```
HTTP 端点(Controller @GetMapping/@PostMapping)
  → QueryGenerator.initQueryWrapper(vo, req.getParameterMap())   ← 未声明参数留在 parameterMap
  → ServiceImpl 组装 (orderBy/permissionSql/userId)
  → Mapper 接口 @Param
  → XML ${}
```

每个 sink 必须回答：参数从哪个端点进、经过哪些 VO/Service、**有无过滤/转义/类型强制**（Integer 强制=安全；String 直传=裸奔）。

## 3. 三类 sink 判定模板（可复用）

| sink | 典型来源 | 可控性判定 |
|---|---|---|
| `${orderBy}` | `queryWrapper.getExpression().getOrderBy().getSqlSegment()`（column/order 参数驱动） | **高**：直接注入，重点对象 |
| `${permissionSql}` | `QueryGenerator.installAuthJdbc(Class)` 按角色数据规则拼装，ruleType=4 自定义规则值裸 SQL | 低：DB 配置侧非 HTTP 直控；顺带建议查线上 sys_permission_data_rule 有无自定义规则值 |
| `user_id='${userId}'` | `sysUser.getId()` 登录态 UUID | 极低：潜伏面；同代码里 `getUsername()` 当 userId 的路径才是真隐患（username 可注册/第三方受控） |

## 4. orderBy 注入链（高价值，CVE-2023-1454 类）

```java
// Controller 标准四行（JeecgBoot 各 list 端点）
QueryWrapper<VO> qw = QueryGenerator.initQueryWrapper(vo, req.getParameterMap());
String orderBy = qw.getExpression().getOrderBy().getSqlSegment();  // 用户 column/order 原样进 ORDER BY
// → Service → mapper.getPageList(..., orderBy) → XML <choose>${orderBy}</choose>
```

- column/order 按**逗号拆分多列排序** → payload 放第二元素：
  - 报错：`order=desc,extractvalue(1,concat(0x7e,(select user()),0x7e))`
  - 双列变体：`column=id,(select updatexml(1,concat(0x7e,database(),0x7e),1))&order=desc,asc`
  - 时间盲注：`order=desc,sleep(5)`（ORDER BY 表达式逐行求值，MySQL 成立）
  - 堆叠：需 druid `allowMultiQueries`（默认关）——先 grep 配置，没有就别写堆叠 PoC。
- **报错回显放大器**：application*.yml `include-exception: true / include-stacktrace: ALWAYS / include-message: ALWAYS` = SQL 异常消息直接回客户端，报错注入成本≈0，预期响应直接写"success:false + XPATH syntax error 回显"。
- 业务侧 XML `${orderBy}` 二次裸拼 = 即使框架升级到 3.5.0+ 白名单也可能被多列拆分绕过——"框架修复可被业务侧绕开"是报告加固短板论据。
- choose 块的 otherwise 分支可能本身是坏 SQL（如 `order <col> desc` 缺 BY）——旁注即可，不影响主结论。

## 5. 产出规范（子代理任务契约）

- 报告：中文，证据带 `文件:行号`，四级置信度（高/中/低/极低），每个候选给 PoC 结构（参数名+payload 形态+预期响应差异），**禁止实际发送**。
- 输出 JSON 契约字段：dollar_sinks_total / exploitable_candidates / jeecg_version / report_path。

## 6. 修复方向（写进报告）

- ORDER BY 不支持 `#{}` 占位符 → 白名单 `Map<列名, SQL片段>` 或升级框架 + Controller 侧列名校验。
- `${permissionSql}` / `${userId}` 类直接改 `#{}` 零成本。
