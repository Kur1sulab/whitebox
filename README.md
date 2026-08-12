# whitebox

白盒代码审计技能集（White-box Code Audit Skills）—— AI Agent 用的源码审计 / 逆向分析 / 密码学研究 playbook 合集，共 **35** 个技能。

> 白盒视角：从源码、二进制、配置出发——污点追踪、鉴权矩阵、文件操作链、依赖与密钥扫描、逆向工程、密码分析、取证分析。

## 技能索引

| 技能 | 说明 |
|------|------|
| [code-safety-audit](./code-safety-audit/) | 扫描代码安全漏洞，检测依赖漏洞、密钥泄露和OWASP安全模式。当用户提到安全扫描、漏洞检测、依赖审计、密钥泄露、API key、OWASP、… |
| [credential-scanner](./credential-scanner/) | Scan your project for exposed credentials, API keys, and secrets befor… |
| [cve-yu2](./cve-yu2/) | 证据驱动白盒代码审计与CVE级漏洞发现 — 污点追踪、反幻觉验证、攻击路径优先级、WooYun 88,636案例统计。当用户要求代码审计/漏… |
| [dependency-auditor](./dependency-auditor/) | Audit npm, pip, and Go dependencies that OpenClaw skills try to instal… |
| [deployment-config-audit](./deployment-config-audit/) | 部署配置/凭据审计：deploy/、yml、docker-compose 暴露面与环境差异。 |
| [hack-ai-ml-security](./hack-ai-ml-security/) | >- |
| [hack-anti-debugging-techniques](./hack-anti-debugging-techniques/) | >- |
| [hack-binary-protection-bypass](./hack-binary-protection-bypass/) | >- |
| [hack-classical-cipher-analysis](./hack-classical-cipher-analysis/) | >- |
| [hack-code-obfuscation-deobfuscation](./hack-code-obfuscation-deobfuscation/) | >- |
| [hack-lattice-crypto-attacks](./hack-lattice-crypto-attacks/) | >- |
| [hack-memory-forensics-volatility](./hack-memory-forensics-volatility/) | >- |
| [hack-rsa-attack-techniques](./hack-rsa-attack-techniques/) | >- |
| [hack-smart-contract-vulnerabilities](./hack-smart-contract-vulnerabilities/) | >- |
| [hack-steganography-techniques](./hack-steganography-techniques/) | >- |
| [hack-symbolic-execution-tools](./hack-symbolic-execution-tools/) | >- |
| [hack-symmetric-cipher-attacks](./hack-symmetric-cipher-attacks/) | >- |
| [hack-traffic-analysis-pcap](./hack-traffic-analysis-pcap/) | >- |
| [hack-vm-and-bytecode-reverse](./hack-vm-and-bytecode-reverse/) | >- |
| [hunt-sast-methodology](./hunt-sast-methodology/) | SAST / static analysis hunting methodology — finding vulns in source c… |
| [java-file-chain-audit](./java-file-chain-audit/) | 审计 Java 上传/下载/删除链（.jsp RCE 判定、physicalPath 穿越）。 |
| [java-filechain-source-audit](./java-filechain-source-audit/) | 审计 Java 源码文件操作链（上传/下载/转换/预览）时用：落盘还原、后缀绕过、路径穿越、.jsp RCE 判定。 |
| [lowcode-framework-authz-audit](./lowcode-framework-authz-audit/) | 审计JeecgBoot/若依类二开源码自定义模块越权/状态机/IDOR时用。含零注解根因定位、状态机三维、配置控制面。 |
| [mybatis-xml-sqli-audit](./mybatis-xml-sqli-audit/) | 源码审计 SQL 注入时用：枚举 MyBatis Mapper XML ${} 拼接并做污点追踪。 |
| [pt-cloud-defense](./pt-cloud-defense/) | Detect and break the cloud post-compromise attack chain (AWS / Azure /… |
| [pt-cryptography](./pt-cryptography/) | Cryptanalysis techniques — lattice attacks, padding oracles, weak-RNG … |
| [pt-cve-poc-generator](./pt-cve-poc-generator/) | CVE research, standalone PoC script and report generation. Given a CVE… |
| [pt-cve-risk-score](./pt-cve-risk-score/) | Retrieve CVE risk scores from NVD. Auto-invoked whenever a CVE ID is m… |
| [pt-dfir](./pt-dfir/) | Digital forensics and incident response - Windows event log analysis, … |
| [pt-firewall-review](./pt-firewall-review/) | Evidence-safe firewall ruleset audit reference specification — 22 docu… |
| [pt-pci-secure-software](./pt-pci-secure-software/) | Automated PCI Secure Software Standard (SSS) v2.0 readiness gap-assess… |
| [pt-reverse-engineering](./pt-reverse-engineering/) | Static and dynamic reverse engineering — ELF/PE analysis, custom-VM by… |
| [pt-source-code-scanning](./pt-source-code-scanning/) | Security-focused source code review and SAST. Scans for vulnerabilitie… |
| [pt-ti-ingest](./pt-ti-ingest/) | Threat-intel signal ingest — converts a CVE + affected-asset + claim p… |
| [whitebox-authz-matrix-audit](./whitebox-authz-matrix-audit/) | 白盒鉴权矩阵审计：枚举 Controller 端点对照 anon 白名单，产出来授权攻击面全图。触发：鉴权/未授权审计。 |

## 安装

方式一（Hermes CLI）：

```bash
hermes skills install <技能目录路径>
```

方式二（手动）：将技能目录复制到 Hermes skills 目录（如 `~/AppData/Local/hermes/skills/pentest/`），开新会话生效。

## 声明

本仓库所有内容仅供**授权范围内**的安全测试、本地靶场练习与安全研究使用。对未授权目标的主动测试行为与作者无关。
