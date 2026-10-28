#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""构建/校验 whitebox 技能库索引。

用法：
  python3 tools/index.py build     # 从各 SKILL.md frontmatter 重新生成 README 技能索引
  python3 tools/index.py check     # 只校验，不写文件（CI 用，有问题返回 1）

校验项：
  1. 每个技能目录必须有 SKILL.md，且 frontmatter 含 name/description
  2. name 必须与目录名一致（Agent 按目录名加载，不一致会导致调用失败）
  3. description 必须是**单行**（多行 `>-` 会让索引生成器只取到第一行）
  4. README 的技能索引必须与目录列表完全一致（不多不少）
  5. 技能之间的相对链接（./xxx/ 或 ../xxx/）必须指向存在的目录/文件
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, 'README.md')
BEGIN = '<!-- SKILLS-INDEX:BEGIN -->'
END = '<!-- SKILLS-INDEX:END -->'


def parse_frontmatter(text):
    if not text.startswith('---'):
        return None
    end = text.find('\n---', 3)
    if end < 0:
        return None
    raw = text[3:end].strip('\n')
    meta, key = {}, None
    for line in raw.split('\n'):
        m = re.match(r'^([A-Za-z_][\w-]*):\s*(.*)$', line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            meta[key] = val
        elif key and line.startswith((' ', '\t')):
            meta[key] = (meta.get(key, '') + ' ' + line.strip()).strip()
    return meta


def scan():
    """返回 [(dir, meta_or_None, problems)]"""
    out = []
    for name in sorted(os.listdir(ROOT)):
        d = os.path.join(ROOT, name)
        if not os.path.isdir(d) or name.startswith('.') or name == 'tools':
            continue
        skill = os.path.join(d, 'SKILL.md')
        problems = []
        meta = None
        if not os.path.exists(skill):
            problems.append('缺 SKILL.md')
        else:
            meta = parse_frontmatter(open(skill, encoding='utf-8', errors='replace').read())
            if meta is None:
                problems.append('frontmatter 缺失或格式错误')
            else:
                if not meta.get('name'):
                    problems.append('frontmatter 缺 name')
                elif meta['name'] != name:
                    problems.append(f"name({meta['name']}) != 目录名({name})")
                desc = (meta.get('description') or '').strip()
                if not desc:
                    problems.append('frontmatter 缺 description')
                elif desc in ('>-', '|', '>'):
                    problems.append('description 是多行块（会导致索引只取到符号）')
                elif len(desc) > 400:
                    problems.append(f'description 过长({len(desc)} 字符)')
        out.append((name, meta, problems))
    return out


def render(rows):
    lines = ['## 技能索引', '', '| 技能 | 说明 |', '|------|------|']
    for name, meta, _ in rows:
        desc = (meta or {}).get('description', '').strip().strip('"\'')
        desc = re.sub(r'\s+', ' ', desc)
        if len(desc) > 100:
            desc = desc[:97] + '…'
        lines.append(f'| [{name}](./{name}/) | {desc} |')
    return '\n'.join(lines) + '\n'


def links_problems(rows):
    """检查技能间相对链接"""
    probs = []
    names = {r[0] for r in rows}
    for name, _, _ in rows:
        p = os.path.join(ROOT, name, 'SKILL.md')
        if not os.path.exists(p):
            continue
        text = open(p, encoding='utf-8', errors='replace').read()
        for m in re.finditer(r'\]\((\.{1,2}/[^)\s]+)\)', text):
            link = m.group(1)
            if link.startswith('http'):
                continue
            target = os.path.normpath(os.path.join(ROOT, name, link))
            if not os.path.exists(target):
                # 同仓库其他技能目录
                seg = link.strip('./').split('/')[0]
                if seg in names:
                    continue
                probs.append(f'{name}: 死链 {link}')
    return probs


def do_check(rows):
    bad = 0
    for name, _, problems in rows:
        if problems:
            bad += 1
            print(f'[FAIL] {name}')
            for p in problems:
                print('   -', p)
    lp = links_problems(rows)
    for p in lp:
        print('[LINK]', p)

    # README 与目录一致性
    if os.path.exists(README):
        txt = open(README, encoding='utf-8').read()
        listed = set(re.findall(r'\|\s*\[([^\]]+)\]\(\./([^/]+)/\)', txt))
        listed = {b for _, b in listed}
        actual = {r[0] for r in rows}
        missing = actual - listed
        extra = listed - actual
        if missing:
            print(f'[README] 缺 {len(missing)} 个技能：{sorted(missing)[:6]}')
            bad += 1
        if extra:
            print(f'[README] 多出 {len(extra)} 项：{sorted(extra)[:6]}')
            bad += 1
    print(f'\n共 {len(rows)} 个技能；有问题的 {bad} 个；死链 {len(lp)} 处')
    return 0 if bad == 0 and not lp else 1


def do_build(rows):
    txt = open(README, encoding='utf-8').read()
    block = f'{BEGIN}\n{render(rows)}{END}'
    if BEGIN in txt and END in txt:
        txt = re.sub(re.escape(BEGIN) + r'.*?' + re.escape(END), block, txt, flags=re.S)
    else:
        txt = txt.rstrip() + '\n\n' + block + '\n'
    # 更新技能总数
    txt = re.sub(r'共 \*\*\d+\*\* 个技能', f'共 **{len(rows)}** 个技能', txt)
    open(README, 'w', encoding='utf-8').write(txt)
    print(f'README 已重建（{len(rows)} 个技能）')


def main():
    rows = scan()
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'check'
    if cmd == 'build':
        do_build(rows)
        return do_check(rows)
    return do_check(rows)


if __name__ == '__main__':
    sys.exit(main())
