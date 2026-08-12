# kykms（JeecgBoot 2.4.5 二开，zsk.example.edu /ky）路3 文件链证据

> 本地源码审计 D:\tools\audit\kykms，产出完整报告 route3-filechain.md（同目录 audit/）。以下为关键证据速查，避免下次重推。

## 部署形态（决定性）
- `deploy/docker-compose.yml:70` `java -jar ./jeecg-boot-module-system-2.4.5.jar` = fat jar 内嵌 Tomcat；nginx 80→8080（:72-84）；context-path=/ky（application.yml:108-109）
- 静态仅 classpath：`application.yml:72-75`；upload-dir 默认 `/kykms/KmDocs`（application-docker.yml:2、application-prod.yml:4）；`jeecg.path.webapp=/opt/webapp` 仅 yml 无代码引用
- **upload_webroot_reachable = false（默认）**；.jsp RCE 需 upload-dir 进 webapps/nginx alias + JspServlet

## 关键证据（文件:行号）
- 落盘链：KmFileServiceImpl.java:32-53（UUID + getFileSuffix + transferTo）；BaseConfig.java:66-73 getTodayUploadDir；:75-87 getRelativePath（纯字符串前缀比较）；:89-113 getFile/getFilePath（无 ../ 净化）
- 匿名写盘实锤：KmDocController.java:71-126 uploadDoc（saveFile 先于 saveDoc NPE KmDocServiceImpl.java:275；清理仅 :118 窄分支）；白名单 KMConstant.java:100-114（DB supportFileTypes 空→true）
- 任意文件读链：注册 anon（ShiroConfig.java:93）→ PUT /KM/kmFile/edit（KmFileController.java:74-78，无权限注解）改 physicalPath → GET /KM/kmDoc/previewKmDoc（getKmDoc KmDocServiceImpl.java:1568-1596，FileInputStream + octet-stream）
- 任意文件删链：DELETE /KM/kmDoc/delete（deleteDoc KmDocServiceImpl.java:1478-1514 无状态/归属校验）→ deleteKmFile KmFileServiceImpl.java:155-168（new File(uploadDir, physicalPath)，绝对 child 语义）
- getFileSuffix：StringUtils.java:26-34（lastIndexOf(".") → 后缀内无点，../ 不可达；可注入 / 建子目录）
- 命令执行：OfficeUtils.java:79-126 ProcessBuilder(List) 无注入；KmSysDbBackupController.java:99,277 Runtime.exec("cmd /c ...") Windows-only 需认证
- Tika：TikaUtils.java:50-62 BodyContentHandler(Integer.MAX_VALUE) → zip bomb DoS；触发需认证（KmDocServiceImpl.java:466 / KmDocController.java:621-624）
- onlyoffice：ShiroConfig.java:79 anon 但无控制器 = 死配置；downloadDocOF 注释残留 KmDocServiceImpl.java:1624-1641
- 哈希预言机：KmDocController.java:79-82 sha256 去重报错泄露 originalName
- 附带 anon 规则：ShiroConfig.java:103-110 `/**/*.html|js|css|pdf|jpg|png|ico`
- docker 默认口令：mysql root/root、redis 123456（application-docker.yml:18-33）

## 候选结论（四级置信度）
- ★★★★ 匿名任意后缀写盘（默认形态 ≠ RCE）
- ★★★ 认证任意文件读/删（edit physicalPath 链，读配置→DB/Redis→横向 RCE）
- ★★ .jsp 直落 webroot RCE（需现场确认 upload-dir 实际值）；LibreOffice 转换解析 RCE（依赖 CVE）
- ★★★ Tika 认证 DoS；changePreviewFile 匿名篡改预览（KmDocController.java:730-760，仅校验 pdf 后缀）
