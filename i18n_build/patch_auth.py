#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Патч index.html: упрощение баланса + авторизация/регистрация + OAuth + облачные сохранения."""
import json, sys

PATH = '/workspace/index.html'
src = open(PATH, encoding='utf-8').read()

def must(cond, msg):
    if not cond:
        sys.exit('FAIL: ' + msg)

def rep1(old, new, tag):
    global src
    must(old in src, tag)
    src = src.replace(old, new, 1)

# ============ 1. Баланс: проще ============
for a, b in [
    ("const MAX_ENERGY = 30;", "const MAX_ENERGY = 50;"),
    ("const ENERGY_REGEN_TICKS = 5;", "const ENERGY_REGEN_TICKS = 2;"),
    ("const BASE_CRIT_CHANCE = 0.03;", "const BASE_CRIT_CHANCE = 0.05;"),
    ("const XP_PER_LEVEL_BASE = 200;", "const XP_PER_LEVEL_BASE = 120;"),
    ("const TAX_RATE = 0.10;", "const TAX_RATE = 0.05;"),
    ("const COST_MULTIPLIER = 4.5;", "const COST_MULTIPLIER = 3.0;"),
]:
    rep1(a, b, 'cfg ' + a)

COIN_COSTS = {
    'cost: 100, ': 'cost: 60, ', 'cost: 800, ': 'cost: 400, ', 'cost: 5000, ': 'cost: 2500, ',
    'cost: 30000, ': 'cost: 12000, ', 'cost: 200000, ': 'cost: 70000, ', 'cost: 1500000, ': 'cost: 400000, ',
    'cost: 10000000, ': 'cost: 2500000, ', 'cost: 80000000, ': 'cost: 15000000, ',
    'cost: 700000000, ': 'cost: 90000000, ', 'cost: 6000000000, ': 'cost: 600000000, ',
    'cost: 50000000000, ': 'cost: 4000000000, ', 'cost: 400000000000, ': 'cost: 25000000000, ',
    'cost: 3500000000000, ': 'cost: 150000000000, ', 'cost: 30000000000000, ': 'cost: 900000000000, ',
    'cost: 250000000000000, ': 'cost: 5000000000000, ', 'cost: 2000000000000000, ': 'cost: 25000000000000, ',
    'cost: 20000000000000000, ': 'cost: 120000000000000, ',
}
for a, b in COIN_COSTS.items():
    rep1(a, b, 'coin ' + a)

rep1("type: 'maxEnergy',  value: 15,   bought: 0 }", "type: 'maxEnergy',  value: 25,   bought: 0 }", 'maxEnergyVal')
for old, new in [
    ("cost: 5000,      type: 'maxEnergy'", "cost: 300,       type: 'maxEnergy'"),
    ("cost: 50000,     type: 'regenSpeed'", "cost: 8000,      type: 'regenSpeed'"),
    ("cost: 25000,     type: 'crit'", "cost: 6000,      type: 'crit'"),
    ("cost: 200000,    type: 'critMult'", "cost: 60000,      type: 'critMult'"),
    ("cost: 100000,    type: 'mult'", "cost: 25000,      type: 'mult'"),
    ("cost: 500000,    type: 'auto'", "cost: 120000,      type: 'auto'"),
    ("cost: 20000000,  type: 'mult'", "cost: 3000000,     type: 'mult'"),
    ("cost: 150000000, type: 'auto'", "cost: 20000000,    type: 'auto'"),
    ("cost: 5000000000, type: 'auto'", "cost: 500000000,  type: 'auto'"),
]:
    rep1(old, new, 'upg ' + old)

# ============ 2. Упрощённые тексты эффектов (ru-блок) ============
rep1("eff_energyMax:'+{v} к макс. пулу энергии, который восстанавливается со временем и тратится на каждое касание монеты',",
     "eff_energyMax:'+{v} макс. энергии',", 'ru eff_energyMax')
rep1("eff_critChance:'+{c}% шанс критического касания (x{m})',",
     "eff_critChance:'+{c}% шанс крита',", 'ru eff_crit')
rep1("eff_auto1:'Автодоход +{v}/сек без касаний',", "eff_auto1:'+{v}/сек',", 'ru auto1')
rep1("eff_auto2:'Автодоход +{v}/сек без касаний',", "eff_auto2:'+{v}/сек',", 'ru auto2')
rep1("eff_auto3:'Автодоход +{v}/сек без касаний',", "eff_auto3:'+{v}/сек',", 'ru auto3')

# ============ 3. i18n: подстановка AUTH-словарей в каждый языковой блок ============
auth_ru = json.load(open('/workspace/i18n_build/auth_ru.json', encoding='utf-8'))
auth_en = json.load(open('/workspace/i18n_build/auth_en.json', encoding='utf-8'))
auth_other = json.load(open('/workspace/i18n_build/auth_other_langs.json', encoding='utf-8'))

def js(d):
    return json.dumps(d, ensure_ascii=False, separators=(',', ':'))

AUTH_JS = {'ru': auth_ru, 'en': auth_en}
for k, v in auth_other.items():
    AUTH_JS[k] = v

LANG_ORDER = ['ru','en','de','fr','es','pt','el','tr','zh','th','ja','ko','pl','uk','hi','fi','no','he','ar']
must(len(AUTH_JS) == 19, 'auth dicts count')

count = 0
for lang in LANG_ORDER:
    marker = "%s:{\n" % lang
    idx = src.find(marker)
    must(idx >= 0, 'lang block ' + lang)
    # вставляем AUTH сразу после открытия блока языка
    src = src[:idx + len(marker)] + '_AUTH:' + js(AUTH_JS[lang]) + ',' + src[idx + len(marker):]
    count += 1
must(count == 19, 'inserted all langs')

open(PATH, 'w', encoding='utf-8').write(src)
print('patch step 1 OK, size:', len(src))
