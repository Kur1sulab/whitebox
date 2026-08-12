# kykms 路10 · Utils 全家深挖（2026-08-11 本地白盒）

审计目标：`jeecg-boot-module-KM/src/main/java/org/jeecg/modules/KM/common/utils/`（11 类）+ `common/rules/SerialNumberRule.java`。产出 `D:\tools\audit\kykms\audit\route10-utils.md`。
仓库为 src 抽取版（无 pom.xml/jar）→ 依赖版本只能由 import + 年代推断，标★中置信。

## 关键链路（全部证据文件:行号）

- **soffice 转换链（解析 RCE 面）**：`KmDocController.uploadDoc:73` → `KmDocServiceImpl.saveDoc:324-327`（ConvertFileTypes 命中→WaitConvert）→ `:363-364` 异步 `convertDocSync` → `:390` `OfficeUtils.convertPdf(baseConfig.getSofficePath(), file, targetDir)` → soffice `--headless --convert-to pdf` 解析攻击者文档。CVE-2023-2255 类取决于部署版（prod=/usr/bin/soffice，`application-prod.yml:7`）。
- **ProcessBuilder 判死**：`OfficeUtils.java:95` ProcessBuilder(List) 无 shell（Linux execve / Windows CreateProcess，`& | < >` 对 CreateProcess 为字面量仅 cmd.exe 解释）→ 命令注入不存在（★★★★高）。sofficePath=yml 静态配置（`BaseConfig.java:49-55`、`application-prod.yml:25`），outputDir 服务端派生，srcFile=UUID+白名单后缀落盘（`KmFileServiceImpl.java:40`）→ argv 全不可控。
- **后缀→存储路径拼接**：`KmFileServiceImpl.saveFile:38-40` `new File(todayDir, fileId+"."+suffix)`，suffix 可含 `/ \ ..` 成分（`StringUtils.getFileSuffix:26-34` 只 lastIndexOf(".")+小写）；兜底=uploadDoc:75 白名单 `isFileTypeSupport`（`KMConstant.java:100-114`），**配置缺失时 return true 全放行**（:110-112）——白名单默认开才是真绕过点。
- **Tika 全链路**：`KmDocServiceImpl.ftiIndexDocBase:443-517`：`:466` parseContent → `:487` setContent → `:489` saveDocToEs → `:671-677` IndexRequest 进 ES。二次注入=索引投毒/存储 XSS（前端渲染依赖）；`BodyContentHandler(Integer.MAX_VALUE)`（`TikaUtils.java:54`）无输出上限→内存 DoS；同步入口 `KmDocController.docDPCheck:620-643`（checkType=2，docId 可控）→ 认证后反复触发解析 CPU DoS；CVE-2022-30126（OOXML 日期正则 ReDoS）适用 tika <1.28.2（import 推断 1.24-1.26：`TikaUtils.java:5-9` AutoDetectParser/UniversalEncodingDetector）。
- **序列号可预测**：`SerialNumberRule.java:9-16` = `Z` + yyMMddHHmmss + `RandomUtils.nextInt(90)+10` → 每秒 90 候选；`KmDocServiceImpl:295` 赋值；**查询过滤条件** `KmDocMapper.xml:65-66`、`KmDocFavouriteMapper.xml:42-43` `and serial_number = #{...}`（参数化无 SQLi，但=枚举 oracle；queryPageList 前置 installAuthJdbc 权限 SQL `:167` → 权限范围内枚举）。
- **XFF 全信任**：`IpUtils.java:12-47` 依次取 x-forwarded-for（首段）/Proxy-Client-IP/WL-Proxy-Client-IP/HTTP_CLIENT_IP/HTTP_X_FORWARDED_FOR/X-Real-IP→getRemoteAddr，无代理白名单无格式校验。16 处调用全进审计：`KmDocVisitRecordServiceImpl.logVisit:80-94` sourceIp 入 DB km_doc_visit_record + ES 访问日志（:100）。限流=用户维度（`KMRedisUtils.java:28-38`，调用 `KmDocServiceImpl:1109/1664/1704`）→ XFF 无绕限价值。onlyoffice 信任模式现版不可达：downloadDocOF 整段注释（`:1625-1641`）、docserviceSiteIp 注释（`:90`）、`downloadKmDoc:1660` `getRemoteAddr().equals("")` 恒 false 死代码。
- **sha256 去重 oracle**：`KmDocController.uploadDoc:79-82` 命中返回 "源文件:"+dupFile.getOriginalName() → 内容存在性探测+已有文件名泄露（低危）。
- **限流工具边界 bug**：`KMRedisUtils.resetUserLimit:41-71` while 循环 leftPop 后 `range(userKey,0,1).get(0)`（:57-68）→ 记录全过期时最后 pop 使 list 空 → IndexOutOfBoundsException → 下载/检索/预览 500，正常使用可踩中（低危 DoS）。
- **其他**：`KmDocServiceImpl:310` `substring(0, lastIndexOf("."))` 无点文件名→SIOOBE（上传必带白名单后缀，难触发）；`saveDoc:319-330` fileType 决定转换分支；importExternalFile 仅 `fileScanImportJob` 定时任务调用（非 HTTP 直达，后缀无白名单但不可直接触达）。

## 输出契约备忘

子代理任务要求"final response 必须是单个 JSON 对象"（含 report_path）时：只输出该 JSON，可加 ```json 围栏，前后零 prose；四个键 command_injection_points/xff_spoofing_impact/serial_predictable/report_path（required: command_injection_points + report_path）。
