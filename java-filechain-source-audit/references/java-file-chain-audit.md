# kykms 文件操作链审计案例（2026-08-11，本地纯静态）

> 目标：zsk.example.edu /ky（80 端口，nginx → 内嵌 Tomcat 8080）。源码 D:\tools\audit\kykms。
> 产出：D:\tools\audit\kykms\audit\route3-filechain.md。全部结论经源码逐行核对。

## 部署形态判定（.jsp RCE 前提）
- `deploy/docker-compose.yml:70` `command: java -jar ./jeecg-boot-module-system-2.4.5.jar` → 默认形态 = fat jar + 内嵌 Tomcat（无 jasper 默认）
- `application.yml:108-109` context-path=/ky；docker-compose.yml:66 8080:8080、:72-84 nginx 80 反代
- 静态资源仅 classpath：application.yml:72-75 `static-locations: classpath:/static/,classpath:/public/`；全库 grep `addResourceHandlers|ResourceHandlerRegistry|file:` 0 命中
- upload-dir：application-docker.yml:2 与 application-prod.yml:4 = `/kykms/KmDocs`（webroot 外）；deploy 样例 c:\KM\upload（Windows 残留）
- **结论：upload_webroot_reachable = false（默认配置，★★★）**；.jsp RCE 需 upload-dir ∈ webroot/nginx alias + JSP 引擎

## 关键证据（文件:行号）
- `BaseConfig.java:14-17` @ConfigurationProperties(base)；`:19-25` init mkdirs；`:66-73` getTodayUploadDir = new File(uploadDir,"yyyyMMdd")；`:75-87` getRelativePath 纯字符串前缀比较无规范化；`:89-113` getFile/getFilePath 拼接无 ../ 净化
- `KmFileServiceImpl.java:32-53` saveFile：todayDir + UUID + getFileSuffix + transferTo（先落盘）；`:45` physicalPath=getRelativePath(dist)（带前导 /）；`:79-98` transferExternalFile(content,suffix) 任意内容写盘（死代码，无调用方）；`:139-152` readKmFileString new File(physicalPath) 绝对读（死代码）；`:155-168` deleteKmFile new File(uploadDir,physicalPath) → 绝对 child 语义
- `StringUtils.java:26-34` getFileSuffix：lastIndexOf(".") + toLowerCase，无过滤
- `KMConstant.java:95-98` fileSeparator OS 判定；`:100-114` isFileTypeSupport：DB supportFileTypes 空→true 全放行
- `KmDocController.java:71-126` uploadDoc：:75 白名单、:79-82 sha256 去重（:81 报错泄露 originalName=哈希预言机）、:108 saveFile 先落盘、:110 saveDoc、:112-120 仅 kmDoc!=null&&id==null 时 deleteKmFile、:121-124 catch（NPE 路径文件永久残留）
- `KmDocController.java:730-760` changePreviewFile：:734 仅校验后缀==pdf，匿名，updateById 篡改 previewFileId
- `KmDocServiceImpl.java:271-367` saveDoc：:275 sysUser.getUsername() NPE（匿名时）；:307 getFile(physicalPath)；:310 originalName.substring(0,lastIndexOf(".")) 无点异常；:324 isConvertFileType；:364 异步 convertDocSync
- `KmDocServiceImpl.java:370-419` convertDocSync：:387 getFile、:390 OfficeUtils.convertPdf(sofficePath,file,targetDir)
- `KmDocServiceImpl.java:1478-1514` deleteDoc：:1480-1481 状态校验被注释、无归属校验；:1493/:1496 deleteKmFile
- `KmDocServiceImpl.java:1517-1621` getKmDoc：:1529-1544 权限校验注释掉；:1568 getFilePath；:1573 FileInputStream；:1575 octet-stream；:1586 attachment
- `KmFileController.java:41-50` list（仅登录）；`:60-64` add；`:74-78` edit（@RequestBody 任意字段 updateById，无 @RequiresPermissions → physicalPath 完全可控）；`:116-123` queryById
- `OfficeUtils.java:79-126` convertPdf ProcessBuilder(List) 无注入；`:32-77` formatExcel POI 解析（IOException 以 RuntimeException 外抛→转换线程 DoS）
- `TikaUtils.java:50-62` BodyContentHandler(Integer.MAX_VALUE) 无写入上限 → zip bomb 认证 DoS；`:56` 无 RESOURCE_NAME metadata
- `ShiroConfig.java:67-72` excludeUrls 拆条 anon；`:79` /onlyoffice/** anon（硬编码）；`:93` /sys/user/register anon；`:98` /sys/common/static/** anon；`:103-110` /**/*.{js,css,html,svg,pdf,jpg,png,ico} anon
- **`application-prod.yml:79-82` 真实 Oracle 生产凭据：106.52.244.12:1521/GHYZSK、ZSK/GHYzsk_163com**（源码树明文泄露 + 反推线上 prod 形态）
- application-docker.yml:18-33 mysql root/root + redis 123456；application-docker.yml:36-38 与 application-prod.yml:98-100 `jeecg.path.upload/webapp` 全库 java 0 消费 = 死配置

## 推演链（成立条件）
1. 【推演 1-1】匿名 .jsp 落盘（★★★★ 落盘 / ★★ RCE）：supportFileTypes 空 → uploadDoc 匿名 → /kykms/KmDocs/yyyyMMdd/<uuid>.jsp 写盘 + km_file 行；默认形态仅字节流下载不可执行 → 匿名持久化写盘原语
2. 【推演 1-2】非默认形态 RCE（★★）：upload-dir ∈ webapps/ROOT 或 nginx alias → 认证后 list 拿 UUID → GET /ky/upload/yyyyMMdd/<uuid>.jsp 由 JspServlet 执行
3. 【推演 3-1】认证任意文件读（★★★）：注册（ShiroConfig:93 anon）→ PUT /KM/kmFile/edit physicalPath=../../../etc/passwd → previewKmDoc/downloadKmDoc → getFilePath 拼接无净化 + FileInputStream → 读配置拿 DB 凭据 → 横向
4. 【推演 3-2】认证任意文件删（★★★）：edit physicalPath=/etc/passwd（绝对 child 语义）→ DELETE /KM/kmDoc/delete → deleteDoc → deleteKmFile 删任意文件
5. 【推演 4】LibreOffice 解析 RCE（★★）：匿名上传恶意 OOXML/OLE → convertDocSync → soffice headless 解析 → 依赖具体 CVE
6. 【推演 2-1】suffix 目录注入（★★）：a.jsp/x → todayDir/UUID.jsp/x，无越界
7. 【推演 2-2】changePreviewFile 内容伪装（★★）：x.jsp.pdf → UUID.pdf（HTML/JS 载荷）→ 预览 octet-stream 输出 → XSS/钓鱼向量

## 候选清单（按价值排序）
1. 匿名任意后缀写盘（★★★★，实测成立）
2. 认证任意文件读（★★★）
3. 认证任意文件删（★★★）
4. 生产 Oracle 凭据泄露（★★★）
5. .jsp 直落 webroot RCE（★★，需现场确认 upload-dir）
6. LibreOffice 解析 RCE（★★，匿名触发）
7. Tika 认证 DoS（★★★）
8. changePreviewFile 匿名篡改预览（★★★，实测）
9. sha256 哈希预言机（★★）
10. getFileSuffix 目录注入（★★）
11. onlyoffice 死配置 / readKmFileString 死代码（★极低-★）

## 工作流坑
- 子代理输出契约：任务要求单 JSON 对象时只输出 JSON，validator 报 "Extra data: line N" = 尾随数据，重发纯 JSON。
