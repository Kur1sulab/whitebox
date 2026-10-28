#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通过 GitHub Git Data API 推送改动（绕开 git 传输层：本机 git 的 GnuTLS 与代理握手失败）"""
import base64
import json
import os
import subprocess
import sys
import urllib.request

OWNER, REPO = 'Kur1sulab', 'whitebox'
BRANCH = 'main'
WORK = '/tmp/wb_remote/whitebox-main'


def token():
    cred = open(os.path.expanduser('~/.git-credentials')).read().strip()
    return cred.split('://')[1].split(':')[1].split('@')[0]


TOK = token()


def api(path, method='GET', body=None):
    data = json.dumps(body).encode() if body is not None else None
    url = 'https://api.github.com' + path
    print('  →', method, url.replace(TOK, '***')[:110], flush=True)
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={'Authorization': 'Bearer ' + TOK,
                 'Accept': 'application/vnd.github+json',
                 'Content-Type': 'application/json',
                 'User-Agent': 'whitebox-indexer'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def main():
    # 1. 当前远端 HEAD
    head = api(f'/repos/{OWNER}/{REPO}/git/ref/heads/{BRANCH}')['object']['sha']
    base_tree = api(f'/repos/{OWNER}/{REPO}/git/commits/{head}')['tree']['sha']
    print(f'远端 HEAD {head[:10]}  tree {base_tree[:10]}')

    # 2. 收集要推的文件：所有 SKILL.md + tools/index.py + workflow + README
    files = []
    for d in sorted(os.listdir(WORK)):
        p = os.path.join(WORK, d, 'SKILL.md')
        if os.path.isdir(os.path.join(WORK, d)) and os.path.exists(p):
            files.append(f'{d}/SKILL.md')
    for extra in ('tools/index.py', '.github/workflows/validate.yml', 'README.md'):
        if os.path.exists(os.path.join(WORK, extra)):
            files.append(extra)
    print(f'待推文件 {len(files)} 个')

    # 3. 上传 blob
    entries = []
    for rel in files:
        data = open(os.path.join(WORK, rel), 'rb').read()
        blob = api(f'/repos/{OWNER}/{REPO}/git/blobs', 'POST',
                   {'content': base64.b64encode(data).decode(), 'encoding': 'base64'})
        entries.append({'path': rel, 'mode': '100644', 'type': 'blob', 'sha': blob['sha']})
    print(f'blob 上传完成 {len(entries)}')

    # 4. 建 tree（基于远端 tree，未列出的文件保持不变）
    tree = api(f'/repos/{OWNER}/{REPO}/git/trees', 'POST',
               {'base_tree': base_tree, 'tree': entries})
    print('新 tree', tree['sha'][:10])

    # 5. 建 commit
    msg = """feat: 规范化 frontmatter + 索引工具/CI + 3 个新技能

- fix: 34 个 SKILL.md 的 name 与目录名不一致；description 为多行块 `>-`（导致索引只取到符号）
- feat(tools): tools/index.py —— 从 frontmatter 生成/校验 README 索引（name、desc、链接、README 同步）
- ci: .github/workflows/validate.yml —— push/PR 校验索引与 README 同步
- feat(skills): patch-diff-variant-hunting（补丁差分→变种狩猎）、silent-failure-detection（静默失效检测）、mobile-static-analysis（APK/小程序静态审计）
- README: 分类索引补 38 个技能"""
    commit = api(f'/repos/{OWNER}/{REPO}/git/commits', 'POST',
                 {'message': msg, 'tree': tree['sha'], 'parents': [head]})
    print('新 commit', commit['sha'][:10])

    # 6. 更新分支
    upd = api(f'/repos/{OWNER}/{REPO}/git/refs/heads/{BRANCH}', 'PATCH',
              {'sha': commit['sha'], 'force': False})
    print('分支已更新 →', upd['object']['sha'][:10])
    print('URL:', f'https://github.com/{OWNER}/{REPO}/commit/{commit["sha"]}')


if __name__ == '__main__':
    sys.exit(main())
