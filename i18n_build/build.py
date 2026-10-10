#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сборщик: вставляет полные переводы в TRANSLATIONS, чистит GLOSS/LANG_NAMES,
добавляет арабский, обновляет THEMES (согласованные цвета), RTL, fallback t().
"""
import re, sys, json
sys.path.insert(0, '/workspace/i18n_build')
from langs_part1 import LANGS as L1
from langs_part2 import LANGS as L2
from langs_part3 import LANGS as L3

ALL = {}
for d in (L1, L2, L3):
    ALL.update(d)

PATH = '/workspace/index.html'
src = open(PATH, encoding='utf-8').read()

def js_str(s):
    # безопасная JS-строка в двойных кавычках
    return json.dumps(s, ensure_ascii=False)

def render_block(code, dic):
    lines = ["    %s: {" % code]
    keys = list(dic.keys())
    for i, k in enumerate(keys):
        v = js_str(dic[k])
        comma = ',' if i < len(keys)-1 else ''
        lines.append("      %s:%s%s" % (k, v, comma))
    lines[-1] = lines[-1].rstrip(',')  # последняя без запятой уже
    lines.append("    }")
    return "\n".join(lines)

# ---------- 1. Вставка новых блоков после 'en'-блока внутри TRANSLATIONS ----------
m = re.search(r"const TRANSLATIONS = \{", src)
assert m, "TRANSLATIONS not found"
start = m.end() - 1  # позиция '{'

# найдем конец en-блока: баланс скобок от начала объекта en
def find_obj_end(s, brace_pos):
    depth = 0
    i = brace_pos
    in_str = None
    while i < len(s):
        c = s[i]
        if in_str:
            if c == '\\':
                i += 2; continue
            if c == in_str:
                in_str = None
        else:
            if c in ('"', "'", '`'):
                in_str = c
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    raise ValueError("unbalanced")

# позиция начала en-объекта
pen = re.compile(r"\ben:\s*\{").search(src, start)
en_open = src.index('{', pen.start())
en_close = find_obj_end(src, en_open)
insert_at = en_close + 1

order = ['de','fr','es','pt','tr','el','zh','th','ja','ko','pl','hi','fi','no','he','ar']
blocks = []
for code in order:
    assert code in ALL, "missing translations for " + code
    blocks.append(render_block(code, ALL[code]))
new_src = src[:insert_at] + ",\n" + ",\n".join(blocks) + src[insert_at:]

# ---------- 2. Удалить весь GLOSS ----------
g_start = new_src.index("const GLOSS = {")
g_open = new_src.index('{', g_start)
g_close = find_obj_end(new_src, g_open)
# захватим и точку с запятой
tail = g_close + 1
if new_src[tail] == ';':
    tail += 1
# захватим предшествующий комментарий
pre_comment = new_src.rfind("// Аннотации", 0, g_start)
line_start = new_src.rfind("\n", 0, pre_comment) + 1 if pre_comment != -1 else g_start
new_src = new_src[:line_start].rstrip() + "\n" + new_src[tail:]

# ---------- 3. LANG_NAMES: добавить ar ----------
old_ln = re.search(r"const LANG_NAMES = \{.*?\};", new_src, re.S)
assert old_ln
new_ln = """const LANG_NAMES = {
    ru:'Русский', en:'English', de:'Deutsch', fr:'Français', es:'Español',
    pt:'Português', el:'Ελληνικά', tr:'Türkçe', zh:'中文', th:'ไทย',
    ja:'日本語', ko:'한국어', pl:'Polski', uk:'Українська', hi:'हिन्दी',
    fi:'Suomi', no:'Norsk', he:'עברית', ar:'العربية'
  };"""
new_src = new_src[:old_ln.start()] + new_ln + new_src[old_ln.end():]

# ---------- 4. t(): убрать GLOSS ----------
old_t = re.search(r"function t\(key, params\) \{.*?\n  \}", new_src, re.S)
assert old_t
new_t = """function t(key, params) {
    const dict = TRANSLATIONS[currentLang] || {};
    const enDict = TRANSLATIONS.en;
    let s = dict[key] !== undefined ? dict[key]
            : (enDict[key] !== undefined ? enDict[key] : key);
    if (params) for (const k in params) s = s.replace(new RegExp('\\\\{' + k + '\\\\}', 'g'), params[k]);
    return s;
  }"""
new_src = new_src[:old_t.start()] + new_t + new_src[old_t.end():]

open(PATH, 'w', encoding='utf-8').write(new_src)
print("OK: translations inserted, GLOSS removed, LANG_NAMES updated, t() cleaned")
