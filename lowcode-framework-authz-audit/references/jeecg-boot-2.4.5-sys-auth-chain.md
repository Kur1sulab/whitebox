# JeecgBoot 2.4.5 sys 模块认证链白盒速查（zsk/kykms 路6 实锤，2026-08-11）

> 来源：`D:\tools\audit\kykms` 白盒审计（路6），报告 `audit/route6-sys-auth.md`。9 个 sys 文件 + ShiroRealm + application-prod.yml。
> 置信度：L1=代码直接证实；L2=机制明确依赖标准组件默认行为；L3=需线上验证；L4=推测。
> 仓库布局（后续路线复用）：`jeecg-2.4.5-sys/`（9 个 sys 文件）、`jeecg-boot/`（KM 模块+shiro base，**无 common 模块源码**）、`deploy/kykms/config/application-prod.yml`（厂商部署配置=金矿，先读它）。

## 注册链 /sys/user/register（SysUserController.java:875-943，anon）
- 参数：body `phone`/`smscode` 必填；`username`/`password`/`email` 可选（username 空=phone，password 空=随机8位）；**SysUser 由 query 参数绑定**（非 @RequestBody）→ 可注 orgCode/avatar/id 等字段透传入库
- 验证码存证：redis **key=手机号明文**，value=6 位数字，TTL600s（LoginController.java:301）；注册成功**不删除**（对比登录成功会 del，LoginController.java:113）→ TTL 内可复用
- **校验顺序缺陷**：username/phone/email 存在性检查（:892-912）先于验证码校验（:913-922）→ 无需验证码即可枚举（"用户名已注册/该手机号已注册/邮箱已被注册"）
- 爆破面：6 位纯数字=10^6，register 无尝试次数限制/无锁定
- 默认角色硬编码 test UUID `ee8626f80f7c2619917b6236f3a7f02b`（:937）

## 短信链 /sys/sms（LoginController.java:237-313，anon）
- 频率限制=单 redis 键（mobile）10 分钟 1 条（:249-254）；**无图形验证码、无 IP/每日限额** → 任意号码批量轰炸（号码列表无上限）；get→send→set 非原子 TOCTOU 可双发
- smsmode：1=注册/0=登录/2=忘记密码；短信内容=固定模板+6位码（**不可控**）；验证码**跨流程通用**（同一 redis key，注册端不校验模板来源）
- sms 注册模式对已注册号返回"手机号已经注册，请直接登录"（:266）→ 手机号 oracle
- **phoneLogin（anon）验证码不消费**（LoginController.java:330-349，比对后无 del）→ 同一码 600s 内可重复签发 token；配合 phoneVerification 续期+回显码形成验证码生命周期失控

## 图形验证码 /sys/randomImage/{key}（LoginController.java:412-429，anon）
- 4 位字符集 60 字符（BASE_CHECK_CODES 去 O/I：26+24+10，60^4≈1.30e7，非 62）；realKey=`MD5(lowerCode+key)`，**key 攻击者可控**，TTL60s
- **失败不删除**（仅登录成功删，:113）→ 同 key+code 在 60s 窗口内无限次登录尝试 → 图形码不构成爆破障碍
- 熵源 hutool RandomUtil=ThreadLocalRandom（非 CSPRNG）
- 与注册/短信/mLogin/phoneLogin 无绑定（这些流程均不校验图形码）

## 登录链 /sys/login（LoginController.java:64-120）与 /sys/mLogin（:437-487）
- 前端 AES 解密**已注释**（:70-73）→ 后端按明文接收；`/sys/getEncryptedString`（anon，:397-405）公开 key/iv → 即使前端加密也等效明文
- **无失败锁定**（checkUserIsEffective 只查不存在/注销/冻结，SysUserServiceImpl.java:362-385）；**mLogin 无验证码** → 干净口令爆破面
- Token 签发：`JwtUtil.sign(username, syspassword)`（:361）—— **JWT 密钥=用户密码哈希**；校验 ShiroRealm.java:126 `JwtUtil.verify(token, username, password)`；改密全量 token 失效；redis TTL=EXPIRE×2
- rememberMe 未实现；登录响应 `obj.put("userInfo", sysUser)`（:386）未脱敏 password/salt（L3 待 SysUser 实体确认）

## ★ 账户接管链（sys 模块，最高价值）
1. 注册拿 test 角色（§注册链）
2. `PUT /sys/user/changePassword {"username":"admin","password":"..."}` —— **无旧密码、无所有权校验**（SysUserController.java:302-310，@RequiresRoles 注释掉）→ 直接重置任意用户密码
3. 免密改密链：`/sys/user/edit` 改受害者手机号（:160-184）→ `/sys/sms` 取己方码 → anon `GET /sys/user/passwordChange?username=&password=&smscode=&phone=`（:1012-1051，ShiroConfig:88）
- 全站 @RequiresRoles/@RequiresPermissions 被注释 → 任意登录用户可 add/edit/delete/frozenBatch/deleteBatch 用户（importExcel 空密码默认 123456，:466-469）

## 枚举面汇总（sys 模块）
- register（anon）：存在性检查先于验证码（§注册链）
- checkOnlyUser（anon，ShiroConfig:84）：SysUser 全字段存在性，"用户账号已存在"
- querySysUser（anon，ShiroConfig:86）：username↔phone 互查并返回映射
- phoneVerification（anon，ShiroConfig:87）：返回手机号对应 username + 验证码**续期 600s**（:996）
- duplicate/check（需 JWT，DuplicateCheckController.java:40-66）：任意表任意字段 COUNT 存在性 oracle；**仅 tableName/fieldName 过 SqlInjectionUtil.filterContent，fieldVal 未过滤**（mapper XML 不在本仓库，${fieldVal} 拼接疑点留待验证）
- category/loadOne（**anon**）：field 列名存在性 + 疑似 SQLi

## 厂商配置炸弹（application-prod.yml + ShiroConfig）
- context-path=`/ky`（yml:9-10）
- `jeecg.shiro.excludeUrls: /category/**,/sys/category/**,/sys/dictItem/**,/KM/EsMgnt/**`（yml:155）→ **sys/category 全控制器匿名**（add/edit/delete/importExcel 写操作 + loadOne）
- `server.error.include-stacktrace/include-exception/include-message: ALWAYS`（yml:5-8）→ 500 响应带全栈+SQL
- druid stat-view-servlet 硬编码 **admin/123456**（yml:79-83）+ `/druid/**` anon（ShiroConfig:108）
- actuator 暴露 metrics,httptrace（yml:16-20）+ `/actuator/**` anon（ShiroConfig:139，源码注释"TODO 存在安全漏洞泄露TOKEN"）→ httptrace 泄露 X-Access-Token

## JwtFilter（官方版 org.jeecg.config.shiro.filters.JwtFilter）
- isAccessAllowed 认证失败**抛 AuthenticationException 而非 return false**（JwtFilter.java:40-48）→ 500 而非 401（黑盒"500 token为空"吻合：realm 抛"token为空!"）；配合 include-stacktrace=ALWAYS 形成全栈泄露
- token 可走 URL 参数 `?token=`（:58-60）→ 日志/Referer 泄露面
- preHandle：CORS 反射 Origin+Allow-Credentials（:78-83）；OPTIONS 一律 200；TenantContext 取 header 未校验（:92-93）
- 路径绕过：Shiro 用 AntPathMatcher 匹配**原始 URI**，不规范化；Tomcat 默认折叠 `//`、拒绝 `/../`、`%2f`（ALLOW_ENCODED_SLASH=false）→ 这些变体到不了 Shiro；**`;` 分号参数是真实缺口**：`/sys/user/changePassword;.js` 命中 anon `/**/*.js`（ShiroConfig:95），Tomcat removeSemicolonContent（servlet 规范默认）剥 `;.js` 后 MVC 正常映射 → 绕过 JWT（L3，机制明确待线上链序验证；同 .html/.css/.svg/.pdf/.jpg/.png/.ico/.ttf/.woff/.js.map）
- CustomShiroFilterFactoryBean 仅关闭 InvalidRequestFilter 非 ASCII 阻断（setBlockNonAscii(false)）
- 与厂商 com.hqcloud.config.shiro.filters.JwtFilter 关系（L4 推断）：官方类 public 非 final，厂商类为同构复刻或子类；本仓库无 hqcloud 源码

## 公告面 /sys/annountCement（SysAnnouncementController）
- 唯一 anon：`/sys/annountCement/show/**`（ShiroConfig:187）→ showContent（SysAnnouncementController.java:462-482）：无 token 仅可看 sendStatus=1 已发布通告；**带任意有效 token 可读任意 id（含未发布）** = 有限 IDOR（需先有 token；id 为自增/雪花可遍历）
- 其余 list/add/edit/delete/doReleaseData/doReovkeData/listByUser/exportXls/importExcel/syncNotic 均需 JWT

## CommonController
- upload（需 JWT）：`biz` 参数无过滤拼路径（:75,129）→ `../` 穿越任意目录写文件；无扩展名白名单/内容校验；文件名=原名+时间戳；`/sys/common/static/**` anon 可匿名下载上传目录文件
- **getshell 判定**：prod upload=/opt/upFiles（application-prod.yml:151）**不在 webapp** → jsp 直传不可执行，需结合穿越把文件写进 webapp 目录才成立（L3）；但 anon static/** 使上传目录文件可匿名下载 = 任意文件托管/分发链面
- passwordChange 为 **GET 方法状态变更**（SysUserController.java:1012-1051）→ CSRF（<img> 触发改密）+ 参数进访问日志/Referer 泄露面
- transitRESTful（需 JWT）：**SSRF** + 自动附调用者 `X-Access-Token`（:360-362）→ 内网探测+凭据外发；URLDecoder.decode 后 RestUtil.request
- static/** view：`imgPath.replace("..","")`（:214）非递归、不挡 `\` 与单点 → 防御性弱点，未找到稳定利用（L3）

## 可迁移白盒模式（本路线新增，与主 SKILL.md 各节互补）
- MyBatis-Plus `QueryWrapper.eq(column, value)` 的 **column 参数原样拼 SQL** → 用户可控列名=SQLi 候选（例：SysCategoryController.loadOne :273 field 参数）
- 验证码三查法：①key 是否与主体强绑定（手机号明文 key=弱绑定）②校验后是否删除（不删=复用）③存在性检查是否先于验证码校验（=无码枚举 oracle）④有无尝试计数
- Shiro 500 vs 401：过滤器抛异常=500 全栈泄露面（配合 include-stacktrace ALWAYS）；正常防御应 401 JSON
- 二开项目标配坑：grep 被注释掉的 `@RequiresRoles/@RequiresPermissions` 行，对照端点映射表即得越权面（主 SKILL.md §4 的补充实例）
- 工具坑：子代理续接会话时 `read_file` 可能因去重缓存返回"File unchanged since last read"且**不带内容**（上下文压缩后缓存仍在）——改用 `terminal sed -n 'a,bp' 文件` / `grep -n` 强制重取证据（带行号），别把"缓存命中"当成"内容还在上下文里"；本路线全部证据即用此法重取
