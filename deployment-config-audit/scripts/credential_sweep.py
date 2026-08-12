#!/usr/bin/env python3
"""仓库配置凭据扫描（纯 stdlib，无网络，本地审计用）。

用法:
    python credential_sweep.py <repo_root> [--mask 8] [--ext yml,yaml,properties,conf]

输出: 按文件分组的 "行号 | 类型 | 值(打码) | 占位?"，自动跳过注释行与占位符。
用途: 白盒审计 S2 步骤的机械部分；人工再精读 yml 确认归属与上下文。
"""
import os
import re
import sys
import argparse

# (类型, 正则) —— 匹配 "key: value" / "key = value" 且值非空
PATTERNS = [
    ("jdbc-url", re.compile(r"^\s*url\s*[:=]\s*(jdbc:[^\s'\"#]+)", re.I)),
    ("password", re.compile(r"^\s*[\w.-]*(?:password|passwd|pwd)\s*[:=]\s*([^\s'\"#]+)", re.I)),
    ("username", re.compile(r"^\s*[\w.-]*(?:username|user|loginUsername)\s*[:=]\s*([^\s'\"#]+)", re.I)),
    ("secret/key/token", re.compile(r"^\s*[\w.-]*(?:secret|access[_-]?key|secret[_-]?key|token|signing[_-]?key|private[_-]?key)\s*[:=]\s*([^\s'\"#]+)", re.I)),
    ("host/endpoint", re.compile(r"^\s*(?:host|master-host|master-port|endpoint|port)\s*[:=]\s*([^\s'\"#]+)", re.I)),
    ("redis-db", re.compile(r"^\s*database\s*[:=]\s*(\d+)", re.I)),
]

# 上游模板常见占位符 -> 判定为占位而非真实凭据
PLACEHOLDERS = {"??", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "changeme", "your-key", "your-secret", "''", "\"\""}
# 明显非凭据的值（示例域名/URL 模板）——只提示不删除
EXAMPLE_MARKERS = ("example.org", "example.com", "minio.jeecg.com", "static.jeecg.com", "localhost")

def mask(v, n):
    v = v.strip().strip("'\"")
    return v if len(v) <= n else v[:n] + "*" * (len(v) - n)

def scan_file(path, mask_n):
    hits = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        return hits, str(e)
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//", "/*", "*")):
            continue
        for typ, rx in PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            val = m.group(1).strip().strip("'\"")
            if not val or val.lower() in PLACEHOLDERS:
                continue
            if any(mk in val.lower() for mk in EXAMPLE_MARKERS) and typ in ("host/endpoint", "username"):
                continue  # 示例域名噪音
            placeholder = "占位?" if val in ("??", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx") else ""
            hits.append((i, typ, mask(val, mask_n), placeholder))
            break  # 每行只报一个类型
    return hits, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--mask", type=int, default=8, help="打码保留前 N 位（默认 8）")
    ap.add_argument("--ext", default="yml,yaml,properties,conf,config", help="逗号分隔扩展名")
    args = ap.parse_args()

    exts = {e.strip().lstrip(".").lower() for e in args.ext.split(",") if e.strip()}
    total = 0
    for dirpath, _, files in os.walk(args.root):
        # 跳过常见噪音目录
        if any(seg in dirpath for seg in (".git", "node_modules", "target", ".idea", "dist")):
            continue
        for fn in sorted(files):
            if fn.lower().split(".")[-1] not in exts:
                continue
            p = os.path.join(dirpath, fn)
            hits, err = scan_file(p, args.mask)
            if err:
                print(f"# {p} 读取失败: {err}")
                continue
            if hits:
                print(f"== {os.path.relpath(p, args.root)}")
                for lineno, typ, val, ph in hits:
                    print(f"  {lineno} | {typ} | {val} {ph}".rstrip())
                    total += 1
    print(f"\n# 共 {total} 条候选凭据")

if __name__ == "__main__":
    main()
