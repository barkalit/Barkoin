#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
БАРКОИН — сервер: статика + надёжная база данных (SQLite, WAL) + аккаунты.

Без внешних зависимостей (только стандартная библиотека Python).

Запуск:  python3 server.py            (порт 8000)
         PORT=3000 python3 server.py

API:
  POST /api/register   {login,email,password,lang}   -> {ok, token, user}
  POST /api/login      {login,password,lang}         -> {ok, token, user}
  POST /api/oauth      {provider, access_token, lang}-> {ok, token, user} (VK/Google/Yandex/Discord)
  GET  /api/me         Authorization: Bearer <token> -> {ok, user}
  POST /api/logout
  GET  /api/save       -> {ok, save}
  POST /api/save       {save:{...}}                  -> {ok, saved_at}
  GET  /api/online     -> {ok, online}               (игроков в сети за 2 мин)
  GET  /api/leaderboard?limit=50 -> {ok, leaderboard[], online, total_players, me_rank}
  GET  /auth/<p>/start  -> OAuth-редирект на настоящую страницу входа провайдера
  GET  /auth/<p>/callback -> приём кода (PKCE), обмен токена, вход/регистрация
  /.well-known/oauth-authorization-server (для Discord)

Соцсети работают ПО-НАСТОЯЩЕМУ (Authorization Code + PKCE, state, nonce):
нужно зарегистрировать приложение у провайдера и заполнить client_id/secret
в oauth_config.json (см. oauth_config.example.json). Без конфигурации кнопка
честно сообщает об этом и предлагает войти по логину.
"""
import os
import re
import json
import sqlite3
import hashlib
import secrets
import base64
import time
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'barcoin.db')
CONFIG_PATH = os.path.join(BASE_DIR, 'oauth_config.json')
PORT = int(os.environ.get('PORT', '8000'))

SESSION_TTL = 30 * 24 * 3600          # сессия живёт 30 дней
PBKDF2_ITER = 210000
LOGIN_RE = re.compile(r'^[A-Za-zА-Яа-яЁё0-9_.\-]{3,32}$')
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$')
PASSWORD_MIN = 6

PROVIDERS = ('vk', 'google', 'yandex', 'discord')


# ===================== База данных =====================
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=FULL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def init_db():
    conn = db()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS users(
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        login         TEXT NOT NULL UNIQUE COLLATE NOCASE,
        email         TEXT NOT NULL COLLATE NOCASE,
        pass_salt     TEXT,
        pass_hash     TEXT,
        provider      TEXT,
        provider_uid  TEXT,
        avatar_url    TEXT,
        created_at    REAL NOT NULL,
        UNIQUE(provider, provider_uid)
    );
    CREATE TABLE IF NOT EXISTS sessions(
        token      TEXT PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS saves(
        user_id  INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        data     TEXT NOT NULL,
        updated_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    -- сетевой рейтинг: заработок каждого игрока + время последнего действия (онлайн-статус)
    CREATE TABLE IF NOT EXISTS stats(
        user_id   INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        earned    REAL NOT NULL DEFAULT 0,
        balance   REAL NOT NULL DEFAULT 0,
        clicks    INTEGER NOT NULL DEFAULT 0,
        level     INTEGER NOT NULL DEFAULT 1,
        last_seen REAL NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_stats_earned ON stats(earned DESC);
    ''')
    conn.commit()
    conn.close()


# ===================== Пароли =====================
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                             bytes.fromhex(salt), PBKDF2_ITER)
    return salt, dk.hex()


def verify_password(password, salt, stored_hash):
    try:
        _, calc = hash_password(password, salt)
    except Exception:
        return False
    return secrets.compare_digest(calc, stored_hash)


# ===================== Сессии =====================
def create_session(user_id):
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn = db()
    conn.execute('INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)',
                 (token, user_id, now, now + SESSION_TTL))
    conn.execute('DELETE FROM sessions WHERE expires_at < ?', (now,))
    conn.commit()
    conn.close()
    return token


def session_user(token):
    if not token:
        return None
    conn = db()
    row = conn.execute(
        'SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id '
        'WHERE s.token=? AND s.expires_at>?', (token, time.time())).fetchone()
    conn.close()
    return row


def user_public(row):
    return {'id': row['id'], 'login': row['login'], 'email': row['email'],
            'provider': row['provider'], 'avatar': row['avatar_url']}


# ===================== OAuth =====================
OAUTH_ENDPOINTS = {
    'vk': {
        'authorize': 'https://id.vk.com/authorize',
        'token': 'https://id.vk.com/oauth/app/desktop',
        'userinfo': ('https://api.vk.com/method/users.get?fields=photo_100&v=5.131', 'user'),
        'extra_params': {},
    },
    'google': {
        'authorize': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token': 'https://oauth2.googleapis.com/token',
        'userinfo': ('https://openidconnect.googleapis.com/v1/userinfo', None),
        'scopes': 'openid email profile',
    },
    'yandex': {
        'authorize': 'https://oauth.yandex.ru/authorize',
        'token': 'https://oauth.yandex.ru/token',
        'userinfo': ('https://login.yandex.ru/info?format=json', None),
        'scopes': 'login:email login:info',
    },
    'discord': {
        'authorize': 'https://discord.com/api/oauth2/authorize',
        'token': 'https://discord.com/api/oauth2/token',
        'userinfo': ('https://discord.com/api/v10/users/@me', None),
        'scopes': 'identify email',
    },
}


def load_oauth_config():
    try:
        with open(CONFIG_PATH, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def redirect_uri(base_url, provider):
    return base_url.rstrip('/') + '/auth/%s/callback' % provider


def pkce_pair():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    return verifier, challenge


def build_authorize_url(provider, base_url):
    cfg = load_oauth_config().get(provider) or {}
    cid = cfg.get('client_id')
    if not cid:
        return None
    ep = OAUTH_ENDPOINTS[provider]
    state = secrets.token_urlsafe(16)
    verifier, challenge = pkce_pair()
    params = {
        'response_type': 'code',
        'client_id': cid,
        'redirect_uri': redirect_uri(base_url, provider),
        'state': state,
    }
    if provider == 'vk':
        params.update({'scope': cfg.get('scope', ''), 'nonce': secrets.token_urlsafe(12),
                       'code_challenge': challenge, 'code_challenge_method': 'S256',
                       'response_type': 'code'})
    else:
        params['scope'] = cfg.get('scope', ep.get('scopes', ''))
        params['code_challenge'] = challenge
        params['code_challenge_method'] = 'S256'
    params.update(ep.get('extra_params', {}))
    url = ep['authorize'] + '?' + urllib.parse.urlencode(params)
    return url, state, verifier


def http_json(url, data=None, headers=None, method=None):
    body = None
    h = {'User-Agent': 'BarcoinServer/1.0', 'Accept': 'application/json'}
    if headers:
        h.update(headers)
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        h['Content-Type'] = 'application/x-www-form-urlencoded'
    req = urllib.request.Request(url, data=body, headers=h, method=method or ('POST' if data else 'GET'))
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode('utf-8', 'replace'))


def exchange_code(provider, code, verifier, base_url):
    cfg = load_oauth_config().get(provider) or {}
    ep = OAUTH_ENDPOINTS[provider]
    data = {
        'grant_type': 'authorization_code',
        'client_id': cfg.get('client_id'),
        'redirect_uri': redirect_uri(base_url, provider),
        'code_verifier': verifier,
    }
    if provider == 'vk':
        data['code'] = code
        resp = http_json(ep['token'], data)
        # VK id: {"access_token": "...", "user_id": ...}
        tok = resp.get('access_token')
        uid = str(resp.get('user_id', ''))
        info = {}
        try:
            info = http_json(ep['userinfo'][0] + '&access_token=' + urllib.parse.quote(tok))
            res = (info.get('response') or [{}])[0]
            uid = str(res.get('id') or uid)
            return tok, uid, {'first_name': res.get('first_name'),
                              'last_name': res.get('last_name'),
                              'avatar': res.get('photo_200') or res.get('photo_100')}
        except Exception:
            return tok, uid, {}
    data['client_secret'] = cfg.get('client_secret', '')
    data['code'] = code
    resp = http_json(ep['token'], data)
    tok = resp.get('access_token')
    if not tok:
        raise RuntimeError('no access_token')
    hdr = {'Authorization': 'Bearer ' + tok}
    try:
        info = http_json(ep['userinfo'][0], headers=hdr)
    except Exception:
        info = {}
    if provider == 'google':
        uid = info.get('sub', '')
        prof = {'name': info.get('name'), 'email': info.get('email'),
                'avatar': info.get('picture')}
    elif provider == 'yandex':
        uid = info.get('id', '')
        prof = {'name': info.get('real_name') or info.get('display_name'),
                'email': info.get('default_email'),
                'avatar': ('https://avatars.yandex.net/get-yapic/' + info['default_avatar']
                          if info.get('default_avatar') and '/' not in str(info.get('default_avatar'))
                          else info.get('default_avatar'))}
    else:  # discord
        uid = info.get('id', '')
        av = info.get('avatar')
        prof = {'name': info.get('username'), 'email': info.get('email'),
                'avatar': ('https://cdn.discordapp.com/avatars/%s/%s.png' % (uid, av)) if av else None}
    return tok, uid, prof


def find_or_create_provider_user(conn, provider, puid, prof):
    row = conn.execute('SELECT * FROM users WHERE provider=? AND provider_uid=?',
                       (provider, puid)).fetchone()
    if row:
        return row
    name = (prof.get('name') or '').strip()
    email = (prof.get('email') or '').strip()
    login = None
    if name:
        cand = re.sub(r'[^A-Za-z0-9_.\-]', '', name.replace(' ', '_'))[:24]
        if len(cand) >= 3:
            login = cand
    if not login:
        login = '%s_%s' % (provider, puid[:8])
    while conn.execute('SELECT 1 FROM users WHERE login=? COLLATE NOCASE', (login,)).fetchone():
        login = login[:24] + '_' + secrets.token_hex(2)
    if not email:
        email = '%s@%s.oauth' % (puid[:16], provider)
    cur = conn.execute(
        'INSERT INTO users(login,email,pass_salt,pass_hash,provider,provider_uid,avatar_url,created_at)'
        ' VALUES(?,?,?,?,?,?,?,?)',
        (login, email, None, None, provider, puid, prof.get('avatar'), time.time()))
    conn.commit()
    return conn.execute('SELECT * FROM users WHERE id=?', (cur.lastrowid,)).fetchone()


# ===================== HTTP =====================
class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=BASE_DIR, **kw)

    def log_message(self, fmt, *args):
        pass

    # ---------- helpers ----------
    def send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = 0
        raw = self.rfile.read(min(n, 2 * 1024 * 1024)) if n else b''
        try:
            return json.loads(raw.decode('utf-8')) if raw else {}
        except Exception:
            return None

    def bearer(self):
        h = self.headers.get('Authorization', '')
        return h[7:].strip() if h.startswith('Bearer ') else None

    def base_url(self):
        host = self.headers.get('Host') or ('localhost:%d' % PORT)
        proto = self.headers.get('X-Forwarded-Proto', 'http')
        if host.split(':')[0] in ('localhost', '127.0.0.1'):
            proto = 'http'
        return '%s://%s' % (proto, host)

    # ---------- routes ----------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        if path.startswith('/api/'):
            return self.api_get(path, qs)
        if path.startswith('/auth/'):
            return self.auth_get(path, qs)
        if path == '/':
            self.path = '/index.html'
        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith('/api/'):
            return self.api_post(parsed.path)
        self.send_json({'ok': False, 'error': 'not_found'}, 404)

    # ---------- API ----------
    def api_get(self, path, qs):
        if path == '/api/config':
            cfg = load_oauth_config()
            return self.send_json({'ok': True, 'providers': {
                p: bool((cfg.get(p) or {}).get('client_id')) for p in PROVIDERS}})
        if path == '/api/me':
            row = session_user(self.bearer())
            if not row:
                return self.send_json({'ok': False, 'error': 'unauthorized'}, 401)
            return self.send_json({'ok': True, 'user': user_public(row)})
        if path == '/api/save':
            row = session_user(self.bearer())
            if not row:
                return self.send_json({'ok': False, 'error': 'unauthorized'}, 401)
            conn = db()
            srow = conn.execute('SELECT data,updated_at FROM saves WHERE user_id=?',
                                (row['id'],)).fetchone()
            conn.close()
            save = json.loads(srow['data']) if srow else None
            return self.send_json({'ok': True, 'save': save,
                                   'saved_at': srow['updated_at'] if srow else None})
        if path == '/api/online':
            # сколько игроков сейчас в сети (активны за последние 2 минуты)
            conn = db()
            n = conn.execute(
                "SELECT COUNT(*) c FROM stats WHERE last_seen > ?",
                (time.time() - 120,)).fetchone()['c']
            conn.close()
            return self.send_json({'ok': True, 'online': n})
        if path == '/api/leaderboard':
            # сетевой рейтинг: кто больше всех заработал + текущий онлайн
            limit = 50
            try:
                limit = max(1, min(100, int((qs.get('limit') or ['50'])[0])))
            except ValueError:
                pass
            now = time.time()
            conn = db()
            rows = conn.execute(
                '''SELECT u.login login, u.avatar_url avatar, s.earned earned,
                          s.balance balance, s.clicks clicks, s.level level,
                          s.last_seen last_seen
                   FROM stats s JOIN users u ON u.id = s.user_id
                   ORDER BY s.earned DESC LIMIT ?''', (limit,)).fetchall()
            online = conn.execute(
                "SELECT COUNT(*) c FROM stats WHERE last_seen > ?",
                (now - 120,)).fetchone()['c']
            total = conn.execute("SELECT COUNT(*) c FROM stats").fetchone()['c']
            me_rank = None
            bearer_row = session_user(self.bearer())
            if bearer_row:
                mine = conn.execute('SELECT earned FROM stats WHERE user_id=?',
                                    (bearer_row['id'],)).fetchone()
                if mine:
                    me_rank = conn.execute(
                        'SELECT COUNT(*) c FROM stats WHERE earned > ?',
                        (mine['earned'],)).fetchone()['c'] + 1
            conn.close()
            lb = [{'login': r['login'], 'avatar': r['avatar'],
                   'earned': r['earned'], 'balance': r['balance'],
                   'clicks': r['clicks'], 'level': r['level'],
                   'online': bool(now - r['last_seen'] < 120)} for r in rows]
            return self.send_json({'ok': True, 'leaderboard': lb,
                                   'online': online, 'total_players': total,
                                   'me_rank': me_rank})
        return self.send_json({'ok': False, 'error': 'not_found'}, 404)

    def api_post(self, path):
        body = self.read_body()
        if body is None:
            return self.send_json({'ok': False, 'error': 'bad_json'}, 400)

        if path == '/api/register':
            login = (body.get('login') or '').strip()
            email = (body.get('email') or '').strip().lower()
            password = body.get('password') or ''
            # подтверждение пароля проверяет фронтенд; сервер сверяет, только
            # если поле прислали (иначе это не ошибка формата)
            confirm = body.get('confirm')
            lang = body.get('lang') if body.get('lang') in (
                'ru','en','de','fr','es','pt','el','tr','zh','th','ja','ko',
                'pl','uk','hi','fi','no','he','ar') else 'ru'
            if not LOGIN_RE.match(login):
                return self.send_json({'ok': False, 'error': 'bad_login'}, 400)
            if not EMAIL_RE.match(email):
                return self.send_json({'ok': False, 'error': 'bad_email'}, 400)
            if len(password) < PASSWORD_MIN:
                return self.send_json({'ok': False, 'error': 'weak_password'}, 400)
            if confirm is not None and password != confirm:
                return self.send_json({'ok': False, 'error': 'password_mismatch'}, 400)
            conn = db()
            if conn.execute('SELECT 1 FROM users WHERE login=? COLLATE NOCASE', (login,)).fetchone():
                conn.close()
                return self.send_json({'ok': False, 'error': 'login_taken'}, 409)
            if conn.execute('SELECT 1 FROM users WHERE email=? COLLATE NOCASE', (email,)).fetchone():
                conn.close()
                return self.send_json({'ok': False, 'error': 'email_taken'}, 409)
            salt, ph = hash_password(password)
            cur = conn.execute(
                'INSERT INTO users(login,email,pass_salt,pass_hash,created_at) VALUES(?,?,?,?,?)',
                (login, email, salt, ph, time.time()))
            uid = cur.lastrowid
            default_save = json.dumps({'lang': lang, 'theme': 'default'})
            conn.execute('INSERT INTO saves(user_id,data,updated_at) VALUES(?,?,?)',
                         (uid, default_save, time.time()))
            conn.commit()
            conn.close()
            token = create_session(uid)
            row = db().execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
            return self.send_json({'ok': True, 'token': token, 'user': user_public(row)})

        if path == '/api/login':
            login = (body.get('login') or '').strip()
            password = body.get('password') or ''
            conn = db()
            row = conn.execute('SELECT * FROM users WHERE login=? COLLATE NOCASE',
                               (login,)).fetchone()
            conn.close()
            if not row or not row['pass_hash'] or \
               not verify_password(password, row['pass_salt'], row['pass_hash']):
                return self.send_json({'ok': False, 'error': 'bad_credentials'}, 401)
            token = create_session(row['id'])
            return self.send_json({'ok': True, 'token': token, 'user': user_public(row)})

        if path == '/api/logout':
            conn = db()
            conn.execute('DELETE FROM sessions WHERE token=?', (self.bearer() or '',))
            conn.commit()
            conn.close()
            return self.send_json({'ok': True})

        if path == '/api/oauth':
            # ручной ввод уже полученного токена провайдера (например, из расширения)
            provider = (body.get('provider') or '').lower()
            access = body.get('access_token') or ''
            if provider not in PROVIDERS or not access:
                return self.send_json({'ok': False, 'error': 'bad_request'}, 400)
            ep = OAUTH_ENDPOINTS[provider]
            try:
                info = http_json(ep['userinfo'][0], headers={'Authorization': 'Bearer ' + access})
            except Exception:
                return self.send_json({'ok': False, 'error': 'token_invalid'}, 400)
            if provider == 'vk':
                res = (info.get('response') or [{}])[0]
                puid, prof = str(res.get('id', '')), {'name': res.get('first_name'),
                                                      'avatar': res.get('photo_200')}
            elif provider == 'google':
                puid, prof = str(info.get('sub', '')), {'name': info.get('name'),
                                                        'email': info.get('email'),
                                                        'avatar': info.get('picture')}
            elif provider == 'yandex':
                puid, prof = str(info.get('id', '')), {'name': info.get('real_name'),
                                                       'email': info.get('default_email')}
            else:
                puid, prof = str(info.get('id', '')), {'name': info.get('username'),
                                                       'email': info.get('email')}
            if not puid:
                return self.send_json({'ok': False, 'error': 'token_invalid'}, 400)
            conn = db()
            row = find_or_create_provider_user(conn, provider, puid, prof)
            conn.close()
            token = create_session(row['id'])
            return self.send_json({'ok': True, 'token': token, 'user': user_public(row)})

        if path == '/api/save':
            row = session_user(self.bearer())
            if not row:
                return self.send_json({'ok': False, 'error': 'unauthorized'}, 401)
            save = body.get('save')
            if not isinstance(save, dict):
                return self.send_json({'ok': False, 'error': 'bad_save'}, 400)
            payload = json.dumps(save, ensure_ascii=False)
            if len(payload) > 1024 * 1024:
                return self.send_json({'ok': False, 'error': 'too_large'}, 413)
            conn = db()
            # защита от накрутки рейтинга: сервер хранит МАКСИМУМ достижений,
            # поэтому переписать результат меньшим значением нельзя
            prev = conn.execute('SELECT earned FROM stats WHERE user_id=?', (row['id'],)).fetchone()
            prev_earned = float(prev['earned']) if prev else 0.0
            def num(key, default=0.0):
                try: return max(0.0, float(save.get(key, default)))
                except (TypeError, ValueError): return default
            earned = max(prev_earned, num('totalEarned'))
            balance = num('balance')
            clicks = int(num('totalClicks'))
            lvl = int(num('playerLevel', 1))
            conn.execute(
                'INSERT INTO saves(user_id,data,updated_at) VALUES(?,?,?) '
                'ON CONFLICT(user_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at',
                (row['id'], payload, time.time()))
            conn.execute(
                'INSERT INTO stats(user_id,earned,balance,clicks,level,last_seen) VALUES(?,?,?,?,?,?) '
                'ON CONFLICT(user_id) DO UPDATE SET '
                'earned=MAX(stats.earned,excluded.earned), balance=excluded.balance, '
                'clicks=MAX(stats.clicks,excluded.clicks), level=MAX(stats.level,excluded.level), '
                'last_seen=excluded.last_seen',
                (row['id'], earned, balance, clicks, lvl, time.time()))
            conn.commit()
            conn.close()
            return self.send_json({'ok': True, 'saved_at': time.time()})

        return self.send_json({'ok': False, 'error': 'not_found'}, 404)

    # ---------- OAuth flow ----------
    def auth_get(self, path, qs):
        parts = path.strip('/').split('/')
        if len(parts) < 2 or parts[1] not in PROVIDERS:
            return self.send_json({'ok': False, 'error': 'not_found'}, 404)
        provider = parts[1]
        base = self.base_url()
        if len(parts) >= 3 and parts[2] == 'start':
            built = build_authorize_url(provider, base)
            if not built:
                # не настроено — popup-страница с честным сообщением (frontend поймает postMessage)
                return self._auth_result(False, provider, error='not_configured')
            url, state, verifier = built
            cookie = 'bc_oauth=%s|%s; Path=/auth/%s; SameSite=Lax; Max-Age=600' % (
                state, verifier, provider)
            self.send_response(302)
            self.send_header('Location', url)
            self.send_header('Set-Cookie', cookie)
            self.end_headers()
            return
        # callback
        ck = self.headers.get('Cookie', '')
        m = re.search(r'bc_oauth=([^|]+)\|([^;]+)', ck)
        expected_state, verifier = (m.group(1), m.group(2)) if m else (None, None)
        got_state = (qs.get('state') or [''])[0]
        code = (qs.get('code') or [''])[0]
        err = (qs.get('error') or [''])[0]
        # clear cookie
        expire = 'Set-Cookie', 'bc_oauth=; Path=/auth/%s; Max-Age=0' % provider
        if err:
            self.send_response(302)
            self.send_header(*expire)
            self.end_headers()
            return self._auth_result(False, provider, error='denied')
        if not code or not m or got_state != expected_state:
            self.send_response(302)
            self.send_header(*expire)
            self.end_headers()
            return self._auth_result(False, provider, error='state_mismatch')
        try:
            _tok, puid, prof = exchange_code(provider, code, verifier, base)
        except Exception as e:
            self.send_response(302)
            self.send_header(*expire)
            self.end_headers()
            return self._auth_result(False, provider, error='exchange_failed')
        if not puid:
            self.send_response(302)
            self.send_header(*expire)
            self.end_headers()
            return self._auth_result(False, provider, error='no_identity')
        conn = db()
        row = find_or_create_provider_user(conn, provider, puid, prof)
        conn.close()
        token = create_session(row['id'])
        self.send_response(302)
        self.send_header(*expire)
        self.send_header('Location', '/?oauth=%s&token=%s&login=%s' % (
            provider, urllib.parse.quote(token), urllib.parse.quote(row['login'])))
        self.end_headers()

    def _auth_result(self, ok, provider, error=None):
        # страница-постанщик для popup-окна: пишет результат в localStorage
        # и шлёт postMessage родителю (frontend слушает 'barcoin-oauth')
        html = '''<!doctype html><meta charset="utf-8"><title>OAuth</title>
<script>
var payload={type:'barcoin-oauth',ok:%s,provider:%r,error:%r};
try{localStorage.setItem('barcoin_oauth_result',JSON.stringify(payload))}catch(e){}
try{if(window.opener)window.opener.postMessage(payload,'*')}catch(e){}
document.body.innerHTML='<p style="font-family:sans-serif;padding:2em">%s</p>';
setTimeout(function(){window.close()},400);
</script>''' % (str(ok).lower(), provider, error,
               'OK ✓' if ok else ('Ошибка: ' + (error or '')))
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    init_db()
    print('БАРКОИН сервер: http://localhost:%d  (db: %s)' % (PORT, DB_PATH))
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
