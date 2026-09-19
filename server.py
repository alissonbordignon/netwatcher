#!/usr/bin/env python3
"""
NetWatch (versão simples): monitor de IPv4/FQDN com ping, histórico de quedas,
cadastro de dispositivos e varredura de rede. UM arquivo, ZERO dependências.

    python netwatch.py                     -> abre o painel
    python netwatch.py 10.0.0.0/24         -> muda a rede que já vem preenchida na varredura

A rede a varrer é digitada na própria tela (ex.: 192.168.2.0/24).

Depois abra http://localhost:8000

Aba Portas SNMP: monitora as portas de roteadores e switches (vários equipamentos) por SNMP v2c.
Notificações no Telegram: clique no sininho do cabeçalho e informe o token do bot e o Chat ID.

Opcional: com o nmap instalado (sudo apt install nmap) a varredura também mostra MAC, fabricante e
portas abertas (22, 80, 443...). Sem o nmap ela continua funcionando só com ping + tabela ARP.
"""
import collections
import gzip
import hmac
import ipaddress
import json
import logging
import os
import queue
import random
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import xml.etree.ElementTree as ET
from http.cookies import SimpleCookie
from html import escape as _attr

# ============================== CONFIGURAÇÃO ================================
DEFAULT_SCAN_NETWORK = "192.168.2.0/24"   # só vem preenchida na tela; você pode digitar qualquer outra
# --- Aba "Portas SNMP": os equipamentos são cadastrados pela tela. Estas 3 linhas só valem se o banco ainda
#     não tiver nenhum equipamento (criam o primeiro, chamado "MikroTik") ---
MIKROTIK_HOST = ""                   # IP do equipamento, ex.: "192.168.88.1" (vazio = cadastre pela tela)
MIKROTIK_COMMUNITY = "public"        # community SNMP v2c (somente leitura)
MIKROTIK_PORTS = ["ether1", "ether2", "ether5"]   # interfaces monitoradas do primeiro equipamento
SNMP_INTERVAL = 10                   # segundos entre leituras
SNMP_TIMEOUT = 2                     # segundos de espera por resposta
SNMP_RETRIES = 1                     # novas tentativas antes de considerar sem resposta
LOGO_URL = "https://cdn-icons-png.magnific.com/256/17794/17794572.png"   # link da imagem do logo ao lado do título, ex.: "https://site.com/logo.png"
# --- Telegram: o token do bot e o Chat ID são informados pela tela (sininho no cabeçalho) ---
TG_BATCH_SECONDS = 5                 # avisos que chegam juntos viram uma só mensagem
TG_MAX_LINES = 25                    # itens listados numa mensagem agrupada
# --- Login do painel: um código de 4 números (estilo MFA). "" = sem login. TROQUE o código de exemplo! ---
PANEL_PIN = os.environ.get("NETWATCH_PIN", "0308").strip()   # também pode vir da variável NETWATCH_PIN
SESSION_HOURS = 24                   # quanto tempo o login vale antes de pedir o código de novo
LOGIN_MAX_FAILS = 5                  # erros seguidos antes de bloquear o IP
LOGIN_LOCK_MINUTES = 15              # tempo de bloqueio depois de errar demais
BIND = "0.0.0.0"                     # use "127.0.0.1" para acesso só neste computador
PORT = 8000
# Categorias iniciais: só são usadas na PRIMEIRA execução. Depois, crie/renomeie/exclua pela tela
# (Dispositivos > Gerenciar categorias).
CATEGORIES = ["PCs", "Câmeras", "Modem", "Access Point", "Internet", "Outros"]
DEFAULT_CATEGORY = "Outros"          # usada quando nenhuma é escolhida; não pode ser excluída nem renomeada
CHECK_INTERVAL = 10                  # segundos entre rodadas de ping
PING_TIMEOUT = 2                     # segundos de espera por resposta
FAILS_TO_OFFLINE = 3                 # falhas seguidas para declarar offline
RETRY_INTERVAL = 2                   # quando um ping falha, tenta de novo após N segundos (confirmação rápida)
MONITOR_WORKERS = 64                 # pings simultâneos no monitoramento (aumente se tiver muitos dispositivos)
VERIFY_MAC = True                    # Linux, rede local: confirma que quem responde é o MESMO equipamento (MAC)
RECOVER_CONFIRMATIONS = 2            # respostas seguidas exigidas para sair de "offline" (evita falso retorno)
MAX_SCAN_HOSTS = 4096                # trava de segurança
SCAN_PORTS = [21, 22, 23, 80, 443, 8080, 8443, 3389]   # portas TCP verificadas na varredura (exige nmap); acrescente 554, 3389...
NMAP_TIMEOUT = 180                   # segundos máximos por bloco de hosts no nmap
PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP", 110: "POP3",
              139: "NetBIOS", 161: "SNMP", 443: "HTTPS", 445: "SMB", 554: "RTSP", 993: "IMAPS", 1433: "SQL Server",
              3306: "MySQL", 3389: "RDP", 5900: "VNC", 8000: "HTTP", 8080: "HTTP", 8443: "HTTPS", 8554: "RTSP"}
# Sugestão automática de categoria a partir do fabricante do MAC (só vale se a categoria existir; você
# pode trocar na tela antes de adicionar). Palavras em minúsculas.
CATEGORY_HINTS = {
    "Câmeras": ["hikvision", "dahua", "axis", "reolink", "vivotek", "hanwha", "uniview", "intelbras",
                "amcrest", "foscam", "mobotix", "ezviz", "lorex"],
    "Access Point": ["ubiquiti", "ruckus", "aruba", "meraki", "engenius", "cambium"],
    "Modem": ["zte", "arris", "technicolor", "sagemcom", "fiberhome", "zhone"],
    "PCs": ["dell", "hewlett", "hp inc", "lenovo", "asustek", "gigabyte", "micro-star", "intel corporate",
            "realtek", "liteon", "apple", "microsoft"],
}
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netwatch.db")
# ============================================================================

if len(sys.argv) > 1:
    DEFAULT_SCAN_NETWORK = str(ipaddress.ip_network(sys.argv[1], strict=False))

SCAN_PORTS = [p for p in SCAN_PORTS if isinstance(p, int) and 0 < p < 65536] or [80]
if DEFAULT_CATEGORY not in CATEGORIES:
    CATEGORIES.append(DEFAULT_CATEGORY)

log = logging.getLogger("netwatch")
WIN, MAC = sys.platform.startswith("win"), sys.platform == "darwin"

# ------------------------------- banco de dados -----------------------------
_lock = threading.RLock()
_db = sqlite3.connect(DB_FILE, check_same_thread=False, isolation_level=None)
_db.row_factory = sqlite3.Row
_db.execute("PRAGMA journal_mode=WAL")
_db.execute("PRAGMA foreign_keys=ON")
_db.executescript("""
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  host TEXT NOT NULL UNIQUE COLLATE NOCASE,
  category TEXT NOT NULL DEFAULT 'Outros',
  detail TEXT NOT NULL DEFAULT '',          -- saída resumida do último ping (diagnóstico)
  mac TEXT NOT NULL DEFAULT '', vendor TEXT NOT NULL DEFAULT '',   -- vindos da varredura
  status TEXT NOT NULL DEFAULT 'unknown',   -- online | offline | unknown
  since INTEGER, last_check INTEGER, latency REAL,
  fails INTEGER NOT NULL DEFAULT 0, first_fail INTEGER,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snmp_devices (          -- equipamentos monitorados por SNMP (aba "Portas SNMP")
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL DEFAULT '',
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 161,
  community TEXT NOT NULL,
  interfaces TEXT NOT NULL,                 -- lista JSON: ["ether1", "ether2"]
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS port_events (           -- quedas de porta dos equipamentos SNMP
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL DEFAULT 0,
  iface TEXT NOT NULL,
  started INTEGER NOT NULL,                 -- link caiu (horário do próprio roteador)
  ended INTEGER,                            -- link voltou (NULL = ainda down)
  reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_port_events ON port_events(iface, started);
CREATE TABLE IF NOT EXISTS outages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  started INTEGER NOT NULL,                 -- ficou offline
  ended INTEGER,                            -- voltou (NULL = ainda offline)
  start_reason TEXT NOT NULL DEFAULT '',    -- o que o ping mostrou quando caiu
  end_reason TEXT NOT NULL DEFAULT ''       -- a resposta que confirmou o retorno
);
""")
# Bancos criados por versões anteriores ainda não têm algumas colunas
_cols = {r["name"] for r in _db.execute("PRAGMA table_info(devices)")}
if "category" not in _cols:
    _db.execute("ALTER TABLE devices ADD COLUMN category TEXT NOT NULL DEFAULT 'Outros'")
if "detail" not in _cols:
    _db.execute("ALTER TABLE devices ADD COLUMN detail TEXT NOT NULL DEFAULT ''")
_ocols = {r["name"] for r in _db.execute("PRAGMA table_info(outages)")}
for _col in ("start_reason", "end_reason"):
    if _col not in _ocols:
        _db.execute("ALTER TABLE outages ADD COLUMN %s TEXT NOT NULL DEFAULT ''" % _col)
for _col in ("mac", "vendor"):
    if _col not in _cols:
        _db.execute("ALTER TABLE devices ADD COLUMN %s TEXT NOT NULL DEFAULT ''" % _col)
if "device_id" not in {r["name"] for r in _db.execute("PRAGMA table_info(port_events)")}:
    _db.execute("ALTER TABLE port_events ADD COLUMN device_id INTEGER NOT NULL DEFAULT 0")
_db.execute("CREATE INDEX IF NOT EXISTS idx_port_events_dev ON port_events(device_id, iface, started)")
if not _db.execute("SELECT 1 FROM snmp_devices LIMIT 1").fetchone():
    # a versão anterior guardava UM equipamento em "settings" (ou nas constantes MIKROTIK_*): vira o primeiro da lista
    _row = _db.execute("SELECT value FROM settings WHERE key='mikrotik'").fetchone()
    try:
        _old = json.loads(_row[0]) if _row else {}
    except ValueError:
        _old = {}
    if (_old.get("host") or MIKROTIK_HOST or "").strip():
        _new_id = _db.execute(
            "INSERT INTO snmp_devices (name, host, port, community, interfaces, created) VALUES (?,?,?,?,?,?)",
            ("MikroTik", (_old.get("host") or MIKROTIK_HOST).strip(), int(_old.get("port") or 161),
             _old.get("community") or MIKROTIK_COMMUNITY, json.dumps(_old.get("interfaces") or MIKROTIK_PORTS),
             int(time.time()))).lastrowid
        _db.execute("UPDATE port_events SET device_id=? WHERE device_id=0", (_new_id,))
    _db.execute("DELETE FROM settings WHERE key='mikrotik'")
_db.execute("""CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  position INTEGER NOT NULL DEFAULT 0
)""")
if not _db.execute("SELECT 1 FROM categories LIMIT 1").fetchone():  # primeira execução: usa a lista do topo
    for _i, _c in enumerate(CATEGORIES):
        _db.execute("INSERT OR IGNORE INTO categories (name, position) VALUES (?, ?)", (_c, _i))
# garante a padrão e as categorias que dispositivos antigos já usam
for _c in [r[0] for r in _db.execute("SELECT DISTINCT category FROM devices")] + [DEFAULT_CATEGORY]:
    _db.execute("INSERT OR IGNORE INTO categories (name, position) VALUES (?, 999)", (_c,))


def q(sql, p=()):
    with _lock:
        return [dict(r) for r in _db.execute(sql, p).fetchall()]


def x(sql, p=()):
    with _lock:
        return _db.execute(sql, p).lastrowid


# ---------------------------------- validação -------------------------------
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOST_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")


def parse_host(value):
    """Valida IPv4 ou FQDN. Também impede injeção de argumentos no ping."""
    v = (value or "").strip().lower().rstrip(".")
    if not v:
        raise ValueError("Informe um IP ou nome (FQDN).")
    try:
        return str(ipaddress.IPv4Address(v))
    except ValueError:
        pass
    if re.fullmatch(r"[\d.]+", v) or not _HOST_RE.match(v):
        raise ValueError("Endereço inválido: %r" % value)
    return v


def default_category():
    r = q("SELECT name FROM categories WHERE name = ? COLLATE NOCASE", (DEFAULT_CATEGORY,))
    return r[0]["name"] if r else DEFAULT_CATEGORY


def category_names():
    """Categorias na ordem de exibição; a padrão ('Outros') sempre por último."""
    dflt = default_category()
    names = [r["name"] for r in q("SELECT name FROM categories ORDER BY position, id") if r["name"] != dflt]
    return names + [dflt]


def parse_category(value):
    """Devolve o nome canônico de uma categoria existente (vazio = padrão)."""
    v = (value or "").strip()
    if not v:
        return default_category()
    for c in category_names():
        if c.lower() == v.lower():
            return c
    raise ValueError("Categoria inválida: %r" % value)


def clean_category_name(value):
    v = re.sub(r"\s+", " ", (value or "").strip())
    if not v:
        raise ValueError("Digite o nome da categoria.")
    if len(v) > 40 or re.search(r"[\x00-\x1f\x7f]", v):
        raise ValueError("Nome inválido: use até 40 caracteres, sem caracteres de controle.")
    return v


def add_category(name):
    name = clean_category_name(name)
    with _lock:
        if any(c.lower() == name.lower() for c in category_names()):
            raise ValueError("Já existe a categoria %r." % name)
        x("INSERT INTO categories (name, position) VALUES (?, (SELECT COALESCE(MAX(position), 0) + 1 FROM categories WHERE position < 999))", (name,))
    return name


def rename_category(old, new):
    with _lock:
        old = parse_category(old) if (old or "").strip() else ""
        if not old or old == default_category():
            raise ValueError("A categoria padrão não pode ser renomeada.")
        new = clean_category_name(new)
        if any(c.lower() == new.lower() and c.lower() != old.lower() for c in category_names()):
            raise ValueError("Já existe a categoria %r." % new)
        x("UPDATE categories SET name = ? WHERE name = ?", (new, old))
        x("UPDATE devices SET category = ? WHERE category = ?", (new, old))
    return new


def delete_category(name):
    """Exclui a categoria; os dispositivos dela passam para a padrão. Retorna quantos foram movidos."""
    with _lock:
        name = parse_category(name) if (name or "").strip() else ""
        dflt = default_category()
        if not name or name == dflt:
            raise ValueError("A categoria padrão não pode ser excluída.")
        moved = len(q("SELECT id FROM devices WHERE category = ?", (name,)))
        x("UPDATE devices SET category = ? WHERE category = ?", (dflt, name))
        x("DELETE FROM categories WHERE name = ?", (name,))
    return moved


def parse_mac_input(value):
    v = (value or "").strip().lower().replace("-", ":")
    if v and not _MAC_RE.match(v):
        raise ValueError("MAC inválido. Use o formato aa:bb:cc:dd:ee:ff.")
    return v


def clean_device_name(value, host):
    """Nome do dispositivo: vazio volta a ser o próprio endereço."""
    v = re.sub(r"\s+", " ", (value or "").strip())
    if len(v) > 100 or re.search(r"[\x00-\x1f\x7f]", v):
        raise ValueError("Nome inválido: use até 100 caracteres, sem caracteres de controle.")
    return v or host


def add_device(name, host, category=None, mac="", vendor=""):
    host = parse_host(host)
    category = parse_category(category)
    name = (name or "").strip()[:100] or host
    mac = (mac or "").strip().lower()
    mac = mac if _MAC_RE.match(mac) else ""
    vendor = (vendor or "").strip()[:100] if mac else ""
    try:
        return x("INSERT INTO devices (name, host, category, mac, vendor, created) VALUES (?,?,?,?,?,?)",
                 (name, host, category, mac, vendor, int(time.time())))
    except sqlite3.IntegrityError:
        raise ValueError("Este endereço já está cadastrado.")


# ----------------------------------- ping -----------------------------------
_LAT = re.compile(r"(?:time|tempo)\s*[=<]\s*([\d.,]+)\s*ms", re.I)
_TTL = re.compile(r"ttl\s*=", re.I)
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_SKIP = re.compile(r"^(ping\s|pinging|disparando|---|\d+\s+(packets|pacotes)|packets:|pacotes|estat|ping statistics|"
                   r"approximate|aproximado|tempos aprox|minimum|m[ií]nimo|round-trip|rtt)", re.I)


def _summary(out):
    """Resume a saída do ping numa linha (a resposta recebida ou o motivo da falha)."""
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    for l in lines:
        if _TTL.search(l):
            return l[:160]
    for l in lines:
        if not _SKIP.search(l):
            return l[:160]
    return "Sem resposta"


def ping(host, timeout=PING_TIMEOUT):
    """1 ICMP echo pelo comando do sistema. Retorna (respondeu, latência_ms, detalhe)."""
    if WIN:
        cmd = ["ping", "-4", "-n", "1", "-w", str(timeout * 1000), host]
    elif MAC:
        cmd = ["ping", "-c", "1", "-W", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-4", "-c", "1", "-W", str(timeout), host]
    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="ignore",
                           timeout=timeout + 3, creationflags=0x08000000 if WIN else 0)  # sem janela no Windows
    except subprocess.TimeoutExpired:
        return False, None, "Sem resposta (tempo esgotado)"
    except FileNotFoundError:
        return False, None, "Comando 'ping' não encontrado neste sistema"
    out = r.stdout or ""
    # A linha de resposta real tem TTL. (O ping do Windows devolve código 0 até em "host inacessível".)
    line = next((l.strip() for l in out.splitlines() if _TTL.search(l)), "")
    if r.returncode != 0 or not line:
        return False, None, _summary(out)
    # Para IP, a resposta tem que vir do PRÓPRIO alvo: roteador/proxy respondendo por ele não vale.
    try:
        target = str(ipaddress.IPv4Address(host))
    except ValueError:
        target = None
    if target:
        ips = _IPV4.findall(line)
        if ips and target not in ips:
            return False, None, "Resposta de outro endereço (%s), ignorada: %s" % (ips[0], line[:100])
    m = _LAT.search(line)
    lat = float(m.group(1).replace(",", ".")) if m else round((time.monotonic() - t0) * 1000, 1)
    return True, lat, line[:160]


# ------------------------- quedas e retornos (estado) ------------------------
def apply_result(dev_id, ok, latency, detail=""):
    with _lock:  # atômico entre threads
        rows = q("SELECT * FROM devices WHERE id=?", (dev_id,))
        if not rows:
            return
        d, t, detail = rows[0], int(time.time()), (detail or "")[:200]
        if ok:
            if d["status"] == "offline":  # VOLTOU
                op = q("SELECT started FROM outages WHERE device_id=? AND ended IS NULL", (dev_id,))
                x("UPDATE outages SET ended=?, end_reason=? WHERE device_id=? AND ended IS NULL", (t, detail, dev_id))
                log.info("ONLINE  %s (%s) voltou: %s", d["name"], d["host"], detail)
                tg_device_event("up", d, detail, t - op[0]["started"] if op else 0)
            since = d["since"] if d["status"] == "online" else t
            x("""UPDATE devices SET status='online', since=?, last_check=?, latency=?, detail=?,
                 fails=0, first_fail=NULL WHERE id=?""", (since, t, latency, detail, dev_id))
            return
        fails, first = d["fails"] + 1, d["first_fail"] or t
        status, since = d["status"], d["since"]
        if status != "offline" and fails >= FAILS_TO_OFFLINE:  # CAIU (queda começa na 1ª falha)
            status, since = "offline", first
            if not q("SELECT id FROM outages WHERE device_id=? AND ended IS NULL", (dev_id,)):
                x("INSERT INTO outages (device_id, started, start_reason) VALUES (?,?,?)", (dev_id, first, detail))
                tg_device_event("down", d, detail, first)
            log.warning("OFFLINE %s (%s) caiu: %s", d["name"], d["host"], detail)
        x("""UPDATE devices SET status=?, since=?, last_check=?, latency=NULL, detail=?,
             fails=?, first_fail=? WHERE id=?""", (status, since, t, detail, fails, first, dev_id))


def arp_mac(ip):
    """MAC do IP na tabela ARP do Linux (só existe para equipamentos da mesma rede local)."""
    try:
        with open("/proc/net/arp") as f:
            next(f, None)
            for line in f:
                c = line.split()
                if len(c) >= 4 and c[0] == ip and c[2] != "0x0":
                    m = c[3].lower()
                    return m if _MAC_RE.match(m) and m != "00:00:00:00:00:00" else ""
    except OSError:
        pass
    return ""


def _probe(dev_id, host):
    """1 ping + confirmação de que quem respondeu é o equipamento cadastrado.
    Retorna (respondeu, latência, detalhe, mac_visto)."""
    ok, lat, detail = ping(host)
    seen = ""
    if ok and VERIFY_MAC:
        seen = arp_mac((_IPV4.findall(detail) or [host])[0])
        row = q("SELECT mac FROM devices WHERE id=?", (dev_id,))
        known = row[0]["mac"] if row else ""
        if seen and known and seen != known:  # outro aparelho está com esse IP (DHCP) ou respondendo por ele
            return False, None, "Resposta de outro equipamento: MAC %s, esperado %s (ignorada)" % (seen, known), seen
        if seen:
            detail = "%s  [MAC %s]" % (detail, seen)
    return ok, lat, detail, seen


def _learn_mac(dev_id, seen):
    if seen:  # primeira vez que o equipamento responde na rede local: guarda o MAC para as próximas conferências
        x("UPDATE devices SET mac=?, vendor=? WHERE id=? AND mac=''", (seen, mac_vendor(seen), dev_id))


def check(dev_id, retry=True):
    """Pinga o dispositivo e aplica o resultado.
    - Falhou: confirma rápido (a cada RETRY_INTERVAL s) em vez de esperar o próximo ciclo.
    - Estava offline e respondeu: exige RECOVER_CONFIRMATIONS respostas seguidas antes de dar como online."""
    rows = q("SELECT host, status FROM devices WHERE id=?", (dev_id,))
    if not rows:
        return
    host, status = rows[0]["host"], rows[0]["status"]
    ok, lat, detail, seen = _probe(dev_id, host)

    if ok and status == "offline":
        for _ in range(RECOVER_CONFIRMATIONS - 1):
            time.sleep(RETRY_INTERVAL)
            ok2, lat2, detail2, seen2 = _probe(dev_id, host)
            if not ok2:
                ok, lat, detail = False, None, "Retorno não confirmado: " + detail2
                break
            lat, detail, seen = lat2, detail2, seen2 or seen
    apply_result(dev_id, ok, lat, detail)
    if ok:
        _learn_mac(dev_id, seen)

    attempts = 1
    while not ok and retry and attempts < FAILS_TO_OFFLINE:
        st = q("SELECT host, status FROM devices WHERE id=?", (dev_id,))
        if not st or st[0]["status"] == "offline":  # removido ou já confirmado offline: não insiste
            return
        time.sleep(RETRY_INTERVAL)
        ok, lat, detail, seen = _probe(dev_id, st[0]["host"])
        apply_result(dev_id, ok, lat, detail)
        if ok:
            _learn_mac(dev_id, seen)
        attempts += 1


_wake = threading.Event()   # acorda o monitor para checar já (ex.: depois de cadastrar vários de uma vez)


def monitor_loop():
    with ThreadPoolExecutor(max_workers=MONITOR_WORKERS) as pool:
        while True:
            _wake.clear()
            t0 = time.monotonic()
            try:
                list(pool.map(check, [r["id"] for r in q("SELECT id FROM devices")]))
            except Exception:
                log.exception("erro na rodada de monitoramento")
            _wake.wait(max(1, CHECK_INTERVAL - (time.monotonic() - t0)))


# ----------------------------------- varredura ------------------------------
_scan_lock = threading.Lock()
scan = {"running": False, "networks": [], "deep": False, "phase": "", "total": 0, "done": 0,
        "found": [], "finished": None, "error": None, "warning": ""}
_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_TRANSIENT = {"DELAY", "PROBE", "INCOMPLETE"}   # estados ARP "ainda decidindo"
PRIVILEGED = (hasattr(os, "geteuid") and os.geteuid() == 0) or bool(os.environ.get("NMAP_PRIVILEGED"))
OUI_FILES = ["/usr/share/nmap/nmap-mac-prefixes", "/usr/local/share/nmap/nmap-mac-prefixes",
             "/opt/homebrew/share/nmap/nmap-mac-prefixes",
             "C:\\Program Files (x86)\\Nmap\\nmap-mac-prefixes", "C:\\Program Files\\Nmap\\nmap-mac-prefixes"]
_OUI = None


def nmap_path():
    return shutil.which("nmap")  # procurado a cada varredura: instalar o nmap não exige reiniciar


def _rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def parse_networks(text):
    """Aceita uma ou várias redes IPv4 (separadas por vírgula/espaço): 192.168.2.0/24, 10.0.0.5, ..."""
    items = [i for i in re.split(r"[,;\s]+", (text or "").strip()) if i]
    if not items:
        raise ValueError("Digite a rede a varrer, por exemplo 192.168.2.0/24.")
    nets = []
    for i in items:
        try:
            n = ipaddress.ip_network(i, strict=False)
        except ValueError:
            raise ValueError("Rede inválida: %r. Use o formato 192.168.2.0/24." % i)
        if n.version != 4:
            raise ValueError("Apenas IPv4 é suportado: %r." % i)
        nets.append(n)
    total = sum(max(1, n.num_addresses - 2) for n in nets)  # confere ANTES de expandir (um /8 tem 16 milhões)
    if total > MAX_SCAN_HOSTS:
        raise ValueError("Rede grande demais: %d endereços (limite %d). Use uma máscara menor, como /24."
                         % (total, MAX_SCAN_HOSTS))
    return nets


def mac_vendor(mac):
    """Fabricante pelo prefixo do MAC (usa a base que acompanha o nmap)."""
    global _OUI
    if int(mac[:2], 16) & 2:  # bit "administrado localmente": celulares modernos usam MAC aleatório
        return "Endereço privado (aleatório)"
    if _OUI is None:
        _OUI = {}
        for path in OUI_FILES:
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line[:1] != "#" and len(line) > 7:
                            _OUI[line[:6].upper()] = line[7:].strip()
                break
            except OSError:
                continue
    return _OUI.get(mac.replace(":", "")[:6].upper(), "")


def neighbors():
    """Tabela ARP do Linux: {ip: (mac, estado)}. REACHABLE = o host respondeu ao ARP há pouco."""
    out = {}
    try:
        r = subprocess.run(["ip", "-4", "neigh", "show"], capture_output=True, text=True, errors="ignore", timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                ip = str(ipaddress.IPv4Address(parts[0]))
            except ValueError:
                continue
            mac = ""
            if "lladdr" in parts and parts.index("lladdr") + 1 < len(parts):
                mac = parts[parts.index("lladdr") + 1].lower()
            out[ip] = (mac if _MAC_RE.match(mac) else "", parts[-1].upper())
        return out
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:  # sem o comando "ip": /proc/net/arp só serve para descobrir o MAC (não tem estado)
        with open("/proc/net/arp") as f:
            next(f, None)
            for line in f:
                c = line.split()
                if len(c) >= 4 and c[2] == "0x2" and _MAC_RE.match(c[3].lower()) and c[3] != "00:00:00:00:00:00":
                    out[c[0]] = (c[3].lower(), "UNKNOWN")
    except OSError:
        pass
    return out


def parse_nmap_xml(xml_text, deep):
    """Converte a saída XML do nmap em [{ip, mac, vendor, ports{porta: estado}, alive}]."""
    recs = []
    for h in ET.fromstring(xml_text).findall("host"):
        ip = mac = vendor = ""
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr", "")
            elif a.get("addrtype") == "mac":
                mac, vendor = a.get("addr", "").lower(), a.get("vendor", "")
        if not ip:
            continue
        st = h.find("status")
        up = st is not None and st.get("state") == "up"
        ports = {}
        for p in h.findall("./ports/port"):
            state = p.find("state")
            try:
                if state is not None:
                    ports[int(p.get("portid"))] = state.get("state", "")
            except (TypeError, ValueError):
                pass
        extra = h.find("./ports/extraports")  # quando todas as portas têm o mesmo estado o nmap resume aqui
        fill = extra.get("state", "filtered") if extra is not None else "filtered"
        for port in SCAN_PORTS:
            ports.setdefault(port, fill)
        responded = any(v in ("open", "closed") for v in ports.values())  # "closed" = recusou = host vivo
        recs.append({"ip": ip, "mac": mac if _MAC_RE.match(mac) else "", "vendor": vendor, "ports": ports,
                     "alive": up if deep else responded})
    return recs


def nmap_scan(nmap, targets, deep):
    ports = ",".join(str(p) for p in SCAN_PORTS)
    cmd = [nmap, "-oX", "-", "-n", "-T4", "--max-retries", "1", "--host-timeout", "60s", "-p", ports]
    if deep:   # também descobre quem bloqueia ping (sondas TCP; com root, ICMP/ARP também)
        cmd += ["-PS" + ports] + (["-PE", "-PA80"] if PRIVILEGED else [])
    else:      # só varre as portas de hosts que já sabemos que existem
        cmd += ["-Pn"]
    try:
        r = subprocess.run(cmd + targets, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                           errors="ignore", timeout=NMAP_TIMEOUT, creationflags=0x08000000 if WIN else 0)
    except subprocess.TimeoutExpired:
        raise RuntimeError("tempo esgotado (%ds) em um bloco de %d endereços" % (NMAP_TIMEOUT, len(targets)))
    try:
        return parse_nmap_xml(r.stdout, deep)
    except ET.ParseError:
        msg = (r.stderr or r.stdout or "").strip().splitlines()
        raise RuntimeError(msg[0][:160] if msg else "sem saída (código %s)" % r.returncode)


def suggest_category(h, existing=None):
    """Categoria sugerida pelo fabricante. `existing` = {nome_minúsculo: nome} das categorias atuais."""
    vendor = (h.get("vendor") or "").lower()
    if not vendor:
        return ""
    if existing is None:
        existing = {c.lower(): c for c in category_names()}
    for cat, words in CATEGORY_HINTS.items():
        if cat.lower() in existing and any(w in vendor for w in words):
            return existing[cat.lower()]
    return ""


def run_scan(nets, deep):
    nmap = nmap_path()
    deep = deep and bool(nmap)
    warnings = []
    try:
        hosts = list(dict.fromkeys(str(h) for n in nets for h in n.hosts()))
        hostset, found = set(hosts), {}

        def add(ip, **info):  # cria/atualiza o registro do host (ignora valores vazios)
            with _scan_lock:
                h = found.get(ip)
                if h is None:
                    h = found[ip] = {"ip": ip, "hostname": "", "latency": None, "mac": "", "vendor": "", "ports": {}}
                    scan["found"].append(h)
                h.update({k: v for k, v in info.items() if v not in (None, "", {})})

        # 1) ping (rápido, sem privilégios)
        with _scan_lock:
            scan.update(phase="ping", total=len(hosts), done=0)

        def probe(ip):
            ok, lat, _ = ping(ip, 1)
            if ok:
                add(ip, hostname=_rdns(ip), latency=lat)
            with _scan_lock:
                scan["done"] += 1

        with ThreadPoolExecutor(max_workers=64) as pool:
            list(pool.map(probe, hosts))

        # 2) tabela ARP: dá o MAC e acha quem existe mas não responde ping (mesma rede local)
        with _scan_lock:
            scan.update(phase="arp", total=0, done=0)
        for _ in range(8):  # o kernel leva alguns segundos para decidir os vizinhos "em dúvida"
            nb = neighbors()
            if not any(st in _TRANSIENT and ip in hostset for ip, (_, st) in nb.items()):
                break
            time.sleep(1)
        for ip, (mac, st) in nb.items():
            if ip in hostset and mac and (st == "REACHABLE" or ip in found):
                add(ip, mac=mac)

        # 3) nmap: portas abertas (+ descoberta extra no modo "deep")
        if nmap:
            targets = hosts if deep else sorted(found, key=ipaddress.IPv4Address)
            size = 256 if deep else 64
            with _scan_lock:
                scan.update(phase="nmap", total=len(targets), done=0)
            for i in range(0, len(targets), size):
                chunk = targets[i:i + size]
                try:
                    for rec in nmap_scan(nmap, chunk, deep):
                        if rec["ip"] in hostset and (rec["alive"] or rec["ip"] in found):
                            add(rec["ip"], mac=rec["mac"], vendor=rec["vendor"], ports=rec["ports"])
                except (RuntimeError, OSError) as e:
                    warnings.append("nmap: %s." % e)
                with _scan_lock:
                    scan["done"] += len(chunk)

        # 4) nomes (DNS reverso) de quem foi achado só por ARP/nmap + fabricante pelo MAC
        with _scan_lock:
            scan.update(phase="names", total=0, done=0)
        pending = [h for h in list(found.values()) if not h["hostname"]]
        with ThreadPoolExecutor(max_workers=16) as pool:
            names = list(pool.map(lambda h: _rdns(h["ip"]), pending))
        with _scan_lock:
            for h, name in zip(pending, names):
                h["hostname"] = name
            for h in found.values():
                if h["mac"] and not h["vendor"]:
                    h["vendor"] = mac_vendor(h["mac"])
        scan["warning"] = " ".join(dict.fromkeys(warnings))[:300]
    except Exception as e:
        log.exception("falha na varredura")
        scan["error"] = str(e)
    finally:
        scan["running"] = False
        scan["phase"] = ""
        scan["finished"] = int(time.time())


def start_scan(text, deep=False):
    """Valida a(s) rede(s) digitada(s) e inicia. Levanta ValueError se inválida; retorna False se já houver uma."""
    nets = parse_networks(text)
    with _scan_lock:
        if scan["running"]:
            return False
        scan.update(running=True, networks=[str(n) for n in nets], deep=bool(deep and nmap_path()), phase="ping",
                    total=0, done=0, found=[], finished=None, error=None, warning="")
    threading.Thread(target=run_scan, args=(nets, bool(deep)), daemon=True).start()
    return True


# ------------- SNMP: portas de roteadores e switches (vários equipamentos) -------------
# Cliente SNMPv2c mínimo (só biblioteca padrão): GET e GETBULK sobre UDP. Lê a IF-MIB
# (estado, velocidade, tráfego e erros das interfaces) e registra quando uma porta cai e volta.
class SnmpError(Exception):
    pass


_SNMP_ERRORS = {1: "resposta grande demais (tooBig)", 2: "OID inexistente (noSuchName)", 3: "valor inválido (badValue)",
                4: "somente leitura (readOnly)", 5: "erro genérico no agente (genErr)"}
_SYS = {"descr": "1.3.6.1.2.1.1.1.0", "uptime": "1.3.6.1.2.1.1.3.0", "name": "1.3.6.1.2.1.1.5.0"}
_IFX = "1.3.6.1.2.1.31.1.1.1"    # ifXTable (nomes, 64 bits, ifHighSpeed)
_IFT = "1.3.6.1.2.1.2.2.1"       # ifTable
_IFOIDS = {"oper": _IFT + ".8", "admin": _IFT + ".7", "last": _IFT + ".9", "speed": _IFT + ".5",
           "hspeed": _IFX + ".15", "hin": _IFX + ".6", "hout": _IFX + ".10", "in32": _IFT + ".10",
           "out32": _IFT + ".16", "inerr": _IFT + ".14", "outerr": _IFT + ".20", "alias": _IFX + ".18"}
_OPER_TEXT = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, body):
    return bytes([tag]) + _ber_len(len(body)) + body


def _ber_int(v):
    return _tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def _ber_oid(oid):
    p = [int(x) for x in oid.strip(".").split(".")]
    body = bytearray([40 * p[0] + p[1]])
    for n in p[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, bytes(body))


def _read(buf, i):
    """Lê um TLV em buf[i:]. Retorna (tag, conteúdo, próxima posição)."""
    tag, ln, i = buf[i], buf[i + 1], i + 2
    if ln & 0x80:
        k = ln & 0x7F
        ln, i = int.from_bytes(buf[i:i + k], "big"), i + k
    if i + ln > len(buf):
        raise ValueError("mensagem truncada")
    return tag, buf[i:i + ln], i + ln


def _dec_oid(b):
    subs, v = [], 0
    for c in b:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            subs.append(v)
            v = 0
    first = subs[0]
    head = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return ".".join(str(n) for n in head + subs[1:])


def _dec_value(tag, b):
    if tag == 0x02:
        return int.from_bytes(b, "big", signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46):       # Counter32, Gauge32, TimeTicks, Counter64
        return int.from_bytes(b, "big")
    if tag == 0x04:
        return b.decode("utf-8", "replace")
    if tag == 0x06:
        return _dec_oid(b)
    if tag == 0x40:
        return ".".join(str(x) for x in b)
    return None                                # NULL, noSuchObject (0x80), noSuchInstance (0x81), endOfMibView (0x82)


def snmp_build(kind, reqid, community, oids, non_rep=0, max_rep=10):
    """Monta a mensagem SNMPv2c. kind: 'get' | 'next' | 'bulk'."""
    if kind == "bulk":
        ptag, head = 0xA5, _ber_int(reqid) + _ber_int(non_rep) + _ber_int(max_rep)
    else:
        ptag, head = (0xA0 if kind == "get" else 0xA1), _ber_int(reqid) + _ber_int(0) + _ber_int(0)
    vbs = b"".join(_tlv(0x30, _ber_oid(o) + b"\x05\x00") for o in oids)
    return _tlv(0x30, _ber_int(1) + _tlv(0x04, community.encode("latin-1")) + _tlv(ptag, head + _tlv(0x30, vbs)))


def snmp_parse(data, reqid):
    """Lê a resposta. Retorna (erro, [(oid, tag, valor)]) ou None se for resposta de outra requisição."""
    tag, msg, _ = _read(data, 0)
    if tag != 0x30:
        raise ValueError("não é SNMP")
    _, _ver, i = _read(msg, 0)
    _, _comm, i = _read(msg, i)
    ptag, pdu, _ = _read(msg, i)
    if ptag != 0xA2:
        raise ValueError("não é uma resposta")
    _, rid, j = _read(pdu, 0)
    if int.from_bytes(rid, "big", signed=True) != reqid:
        return None
    _, es, j = _read(pdu, j)
    _, _ei, j = _read(pdu, j)
    _, vbs, _ = _read(pdu, j)
    out, k = [], 0
    while k < len(vbs):
        _, vb, k = _read(vbs, k)
        _, ob, m = _read(vb, 0)
        vt, vv, _ = _read(vb, m)
        out.append((_dec_oid(ob), vt, _dec_value(vt, vv)))
    return int.from_bytes(es, "big"), out


def snmp_query(cfg, kind, oids, non_rep=0, max_rep=10):
    try:
        ip = socket.gethostbyname(cfg["host"])
    except OSError:
        raise SnmpError("não foi possível resolver %r" % cfg["host"])
    reqid = random.randrange(1, 2 ** 31)
    msg = snmp_build(kind, reqid, cfg["community"], oids, non_rep, max_rep)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _ in range(SNMP_RETRIES + 1):
            try:
                s.sendto(msg, (ip, cfg["port"]))
            except OSError as e:
                raise SnmpError("falha ao enviar: %s" % e)
            end = time.monotonic() + SNMP_TIMEOUT
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    break
                s.settimeout(left)
                try:
                    data, addr = s.recvfrom(65535)
                except socket.timeout:
                    break
                except OSError as e:
                    raise SnmpError("falha ao receber: %s" % e)
                if addr[0] != ip:
                    continue
                try:
                    r = snmp_parse(data, reqid)
                except (ValueError, IndexError):
                    continue
                if r is None:
                    continue
                if r[0]:
                    raise SnmpError("o roteador recusou a consulta: " + _SNMP_ERRORS.get(r[0], "erro %d" % r[0]))
                return r[1]
    raise SnmpError("sem resposta SNMP em %s:%d. Confira o IP, a community, se o SNMP está habilitado no "
                    "roteador e se o firewall libera UDP %d." % (cfg["host"], cfg["port"], cfg["port"]))


def snmp_get(cfg, oids):
    """{oid: valor} (None quando o roteador não tem aquele OID)."""
    out = {}
    for i in range(0, len(oids), 25):   # pacotes pequenos cabem em qualquer MTU
        for oid, _tag, val in snmp_query(cfg, "get", oids[i:i + 25]):
            out[oid] = val
    return out


def snmp_walk(cfg, base, limit=512):
    out, cur = [], base
    while len(out) < limit:
        progressed = False
        for oid, tag, val in snmp_query(cfg, "bulk", [cur], max_rep=10):
            if tag == 0x82 or not oid.startswith(base + "."):
                return out
            out.append((oid, val))
            cur, progressed = oid, True
        if not progressed:
            break
    return out


def snmp_ifmap(cfg):
    """{nome da interface: ifIndex}. No MikroTik ifName é o próprio nome (ether1, ether2...)."""
    rows = snmp_walk(cfg, _IFX + ".1") or snmp_walk(cfg, _IFT + ".2")
    return {str(v): int(oid.rsplit(".", 1)[1]) for oid, v in rows if v is not None}


# ---- equipamentos SNMP (vários), guardados no banco
def snd_list():
    out = []
    for r in q("SELECT * FROM snmp_devices ORDER BY id"):
        try:
            r["interfaces"] = json.loads(r["interfaces"])
        except ValueError:
            r["interfaces"] = []
        out.append(r)
    return out


def snd_get(dev_id):
    return next((d for d in snd_list() if d["id"] == dev_id), None)


def parse_ifaces(value):
    """Nomes das interfaces, separados por vírgula (ex.: ether1, ether2, Gi0/1)."""
    if isinstance(value, str):
        value = re.split(r"[,;\n]+", value)
    names = list(dict.fromkeys(re.sub(r"\s+", " ", i.strip()) for i in (value or []) if isinstance(i, str) and i.strip()))
    if not names:
        raise ValueError("Informe ao menos uma interface (ex.: ether1, ether2). Separe por vírgula.")
    if len(names) > 16 or not all(re.fullmatch(r"[A-Za-z0-9_.:/@+ -]{1,40}", n) for n in names):
        raise ValueError("Interfaces inválidas: use até 16 nomes (ex.: ether1, ether2, Gi0/1), separados por vírgula.")
    return names


_sn_lock = threading.Lock()      # estado lido pela API
_poll_locks = {}                 # uma consulta por vez em cada equipamento
_sn_wake = threading.Event()
SN = {}                          # id do equipamento -> estado da última leitura


def sn_new():
    return {"ok": False, "error": "", "last_poll": None, "sysname": "", "descr": "", "uptime": None, "ifmap": {},
            "ifmap_at": 0, "ports": {}, "prev": {}, "seen": {}, "samples": {}}


def sn_state(dev_id):
    with _sn_lock:
        return SN.setdefault(dev_id, sn_new())


def snd_save(body, dev_id=None):
    """Cadastra (dev_id=None) ou edita um equipamento e já faz uma leitura de teste.
    Retorna (id, erro_do_snmp). Valores inválidos levantam ValueError."""
    cur = None
    if dev_id is not None:
        cur = snd_get(dev_id)
        if not cur:
            raise ValueError("Equipamento não encontrado.")
    host = parse_host(body.get("host") or "")
    name = re.sub(r"\s+", " ", (body.get("name") or "").strip())
    if len(name) > 60 or re.search(r"[\x00-\x1f\x7f]", name):
        raise ValueError("Nome inválido: use até 60 caracteres.")
    comm = body.get("community")
    comm = str(comm) if comm not in (None, "") else (cur["community"] if cur else MIKROTIK_COMMUNITY)
    if not re.fullmatch(r"[\x20-\x7e]{1,64}", comm):
        raise ValueError("Community inválida: use de 1 a 64 caracteres comuns.")
    try:
        port = 161 if body.get("port") in (None, "") else int(body.get("port"))
    except (TypeError, ValueError):
        raise ValueError("Porta SNMP inválida.")
    if not 1 <= port <= 65535:
        raise ValueError("Porta SNMP inválida.")
    names = parse_ifaces(body.get("interfaces"))
    others = [d for d in snd_list() if d["id"] != dev_id]
    if any(d["host"].lower() == host and d["port"] == port for d in others):
        raise ValueError("Este equipamento (IP e porta) já está cadastrado.")
    if not cur and len(others) >= 30:
        raise ValueError("Limite de 30 equipamentos.")
    if cur:
        x("UPDATE snmp_devices SET name=?, host=?, port=?, community=?, interfaces=? WHERE id=?",
          (name, host, port, comm, json.dumps(names), dev_id))
    else:
        dev_id = x("INSERT INTO snmp_devices (name, host, port, community, interfaces, created) VALUES (?,?,?,?,?,?)",
                   (name, host, port, comm, json.dumps(names), int(time.time())))
    if not cur or (cur["host"], cur["port"], cur["community"]) != (host, port, comm):
        with _sn_lock:               # conexão nova: recomeça as leituras do zero
            SN[dev_id] = sn_new()
    return dev_id, sn_poll(snd_get(dev_id))


def snd_delete(dev_id):
    if not snd_get(dev_id):
        return False
    x("DELETE FROM port_events WHERE device_id=?", (dev_id,))
    x("DELETE FROM snmp_devices WHERE id=?", (dev_id,))
    with _sn_lock:
        SN.pop(dev_id, None)
    _poll_locks.pop(dev_id, None)
    return True


# ---- leitura e registro das quedas de porta
def _sn_transition(dev, st, name, state, oper, last, uptime, since_s, now):
    """Abre/fecha eventos de queda. O horário vem do próprio equipamento (ifLastChange), então é exato."""
    did, prev = dev["id"], st["seen"].get(name)
    when = now - since_s if since_s is not None and 0 <= since_s < 10 * 365 * 86400 else now
    when = int(min(when, now))
    open_ev = q("SELECT id, started FROM port_events WHERE device_id=? AND iface=? AND ended IS NULL", (did, name))
    alias = (st["ports"].get(name) or {}).get("alias")
    if state == "down" and not open_ev:
        x("INSERT INTO port_events (device_id, iface, started, reason) VALUES (?,?,?,?)",
          (did, name, when, "Link sem sinal (ifOperStatus=%s)" % _OPER_TEXT.get(oper, oper)))
        log.warning("PORTA %s caiu (%s)", name, dev["name"] or dev["host"])
        tg_port_event("down", dev, name, alias, when)
    elif state != "down" and open_ev:
        x("UPDATE port_events SET ended=? WHERE device_id=? AND iface=? AND ended IS NULL",
          (when if state == "up" else now, did, name))
        log.info("PORTA %s %s (%s)", name, "voltou" if state == "up" else "foi desabilitada", dev["name"] or dev["host"])
        if state == "up":
            tg_port_event("up", dev, name, alias, max(0, when - open_ev[0]["started"]))
    elif (prev and prev["state"] == "up" and state == "up" and last is not None and prev["last"] is not None
          and last != prev["last"] and uptime is not None and prev["uptime"] is not None and uptime >= prev["uptime"]):
        x("INSERT INTO port_events (device_id, iface, started, ended, reason) VALUES (?,?,?,?,?)",
          (did, name, when, when, "Oscilou entre duas leituras (caiu e voltou)"))
    st["seen"][name] = {"state": state, "last": last, "uptime": uptime}


def _sn_poll(dev):
    st = sn_state(dev["id"])
    now, mono = int(time.time()), time.monotonic()
    names, age = dev["interfaces"], now - st["ifmap_at"]
    missing = [n for n in names if n not in st["ifmap"]]
    if not st["ifmap"] or age > 600 or (missing and age > 60):
        ifmap = snmp_ifmap(dev)
        if not ifmap:
            raise SnmpError("o equipamento respondeu, mas não listou interfaces (IF-MIB).")
        info = snmp_get(dev, [_SYS["name"], _SYS["descr"]])
        with _sn_lock:
            st.update(ifmap=ifmap, ifmap_at=now, sysname=str(info.get(_SYS["name"]) or ""),
                      descr=str(info.get(_SYS["descr"]) or ""))
    idx = {n: st["ifmap"].get(n) for n in names}
    oids = [_SYS["uptime"]] + ["%s.%d" % (o, i) for i in idx.values() if i for o in _IFOIDS.values()]
    got = snmp_get(dev, oids)
    uptime = got.get(_SYS["uptime"])
    with _sn_lock:
        for name in names:
            i = idx[name]
            if not i:
                st["ports"][name] = {"name": name, "found": False, "state": "missing"}
                continue
            g = {k: got.get("%s.%d" % (o, i)) for k, o in _IFOIDS.items()}
            oper, admin = g["oper"], g["admin"]
            state = "up" if oper == 1 else ("disabled" if admin == 2 else "down")
            speed = g["hspeed"] or (g["speed"] // 1000000 if g["speed"] and g["speed"] < 4294967295 else 0)
            wide = g["hin"] is not None
            in_oct, out_oct = (g["hin"], g["hout"]) if wide else (g["in32"], g["out32"])
            in_bps = out_bps = None
            prev = st["prev"].get(name)
            if prev and prev[3] != wide:       # passou a informar outro tipo de contador (32 x 64 bits)
                prev = None
            if prev and in_oct is not None and out_oct is not None and mono - prev[0] >= 0.5:  # leituras coladas dão taxa ruidosa
                dt, span = mono - prev[0], 2 ** (64 if wide else 32)
                d_in, d_out = in_oct - prev[1], out_oct - prev[2]
                if d_in < 0 and not wide:      # contador de 32 bits deu a volta
                    d_in += span
                if d_out < 0 and not wide:
                    d_out += span
                if d_in >= 0 and d_out >= 0:   # negativo em 64 bits = equipamento reiniciou: ignora esta leitura
                    in_bps, out_bps = d_in * 8 / dt, d_out * 8 / dt
            if not prev or mono - prev[0] >= 0.5:
                st["prev"][name] = (mono, in_oct, out_oct, wide)
            elif name in st["ports"] and st["ports"][name].get("in_bps") is not None:
                in_bps, out_bps = st["ports"][name]["in_bps"], st["ports"][name]["out_bps"]   # mantém a última taxa válida
            if in_bps is not None:
                st["samples"].setdefault(name, collections.deque(maxlen=180)).append([now, int(in_bps), int(out_bps)])
            since_s = (uptime - g["last"]) / 100 if uptime is not None and g["last"] is not None and uptime >= g["last"] else None
            alias = re.sub(r"[\x00-\x1f\x7f]", " ", g["alias"]).strip()[:200] if isinstance(g["alias"], str) else None   # None = o equipamento não informa
            pct = lambda v: round(min(100.0, v / (speed * 1e6) * 100), 1) if v is not None and speed else None
            st["ports"][name] = {"name": name, "found": True, "index": i, "state": state, "admin": admin, "oper": oper,
                                 "speed": speed, "in_bps": in_bps, "out_bps": out_bps, "in_pct": pct(in_bps),
                                 "out_pct": pct(out_bps), "in_errors": g["inerr"], "out_errors": g["outerr"],
                                 "since": int(now - since_s) if since_s is not None else None, "alias": alias}
            _sn_transition(dev, st, name, state, oper, g["last"], uptime, since_s, now)
        st.update(ok=True, error="", last_poll=now, uptime=uptime / 100 if uptime is not None else None)


def sn_poll(dev):
    """Consulta um equipamento uma vez. Retorna '' se deu certo ou a mensagem de erro."""
    with _poll_locks.setdefault(dev["id"], threading.Lock()):
        try:
            _sn_poll(dev)
            return ""
        except SnmpError as e:
            err = str(e)
        except Exception as e:   # um erro inesperado não pode derrubar a thread de consulta
            log.exception("erro ao consultar %s", dev["host"])
            err = "erro inesperado: %s" % e
        st = sn_state(dev["id"])
        with _sn_lock:
            st.update(ok=False, error=err, last_poll=int(time.time()))
        return err


def sn_snapshot():
    t, devs = int(time.time()), snd_list()
    out = []
    with _sn_lock:
        for d in devs:
            st = SN.get(d["id"]) or sn_new()
            ports = []
            for n in d["interfaces"]:
                p = dict(st["ports"].get(n) or {"name": n, "found": None, "state": "unknown"})
                p["samples"] = list(st["samples"].get(n, []))
                ports.append(p)
            out.append({"id": d["id"], "name": d["name"], "host": d["host"], "port": d["port"], "interfaces": d["interfaces"],
                        "has_community": bool(d["community"]), "ok": st["ok"], "error": st["error"], "last_poll": st["last_poll"],
                        "sysname": st["sysname"], "descr": st["descr"], "uptime": st["uptime"], "ports": ports})
    events = q("SELECT device_id, iface, started, ended, reason FROM port_events ORDER BY started DESC, id DESC LIMIT 200")
    for e in events:
        e["ongoing"], e["duration"] = e["ended"] is None, (e["ended"] or t) - e["started"]
    return {"devices": out, "events": events, "interval": SNMP_INTERVAL}


def sn_loop():
    with ThreadPoolExecutor(max_workers=8) as pool:   # equipamentos fora do ar não atrasam os demais
        while True:
            t0 = time.monotonic()
            try:
                devs = snd_list()
                with _sn_lock:
                    for k in [k for k in SN if k not in {d["id"] for d in devs}]:
                        del SN[k]
                list(pool.map(sn_poll, devs))
            except Exception:
                log.exception("erro na rodada SNMP")
            _sn_wake.wait(max(1, SNMP_INTERVAL - (time.monotonic() - t0)))
            _sn_wake.clear()


# ------------------------------ Telegram (notificações) -----------------------------
# Só biblioteca padrão: chama a Bot API (https://api.telegram.org) por HTTPS. Os avisos entram numa fila e um
# trabalhador os envia em lote (uma queda em massa vira UMA mensagem, não dezenas). O token nunca vai para a página.
class TgError(ValueError):
    def __init__(self, msg, retry=None):
        super().__init__(msg)
        self.retry = retry


_TG_TOKEN_RE = re.compile(r"\d{5,12}:[A-Za-z0-9_-]{20,60}")
_TG_CHAT_RE = re.compile(r"-?\d{1,20}|@[A-Za-z0-9_]{4,32}")
_tg_lock = threading.Lock()
_tg_cfg = None
_tg_state = {"last_ok": None, "last_error": "", "sent": 0}
_tg_queue = queue.Queue(maxsize=500)


def setting_get(key, default=""):
    r = q("SELECT value FROM settings WHERE key=?", (key,))
    return r[0]["value"] if r else default


def setting_set(key, value):
    x("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def tg_config():
    """Configuração atual (em memória; só relê o banco na primeira vez)."""
    global _tg_cfg
    with _tg_lock:
        if _tg_cfg is None:
            cfg = {"enabled": False, "token": "", "chat_id": "", "on_down": True, "on_up": True, "on_ports": True}
            try:
                cfg.update({k: v for k, v in json.loads(setting_get("telegram", "{}")).items() if k in cfg})
            except ValueError:
                pass
            _tg_cfg = cfg
        return dict(_tg_cfg)


def tg_save(body):
    """Valida e grava. O token em branco mantém o atual."""
    global _tg_cfg
    cur = tg_config()
    token = body.get("token")
    token = cur["token"] if token in (None, "") else str(token).strip()
    chat = str(body.get("chat_id") or "").strip()
    new = {"enabled": bool(body.get("enabled")), "token": token, "chat_id": chat, "on_down": bool(body.get("on_down")),
           "on_up": bool(body.get("on_up")), "on_ports": bool(body.get("on_ports"))}
    if token and not _TG_TOKEN_RE.fullmatch(token):
        raise ValueError("Token inválido. Ele tem o formato 123456789:AAE... (copie inteiro do @BotFather).")
    if chat and not _TG_CHAT_RE.fullmatch(chat):
        raise ValueError("Chat ID inválido: use só números (grupos começam com -) ou @nome do canal.")
    if new["enabled"] and (not token or not chat):
        raise ValueError("Para ativar, informe o token do bot e o Chat ID.")
    if new["enabled"] and not (new["on_down"] or new["on_up"] or new["on_ports"]):
        raise ValueError("Marque ao menos um tipo de aviso.")
    setting_set("telegram", json.dumps(new))
    with _tg_lock:
        _tg_cfg = new
        if token != cur["token"]:            # bot novo: esquece o resultado do anterior
            _tg_state.update(last_ok=None, last_error="")


def tg_snapshot():
    c = tg_config()
    with _tg_lock:
        st = dict(_tg_state)
    return {"enabled": c["enabled"], "has_token": bool(c["token"]), "chat_id": c["chat_id"], "on_down": c["on_down"],
            "on_up": c["on_up"], "on_ports": c["on_ports"], "last_ok": st["last_ok"], "last_error": st["last_error"],
            "sent": st["sent"], "queued": _tg_queue.qsize()}


def _tg_message(res):
    """Traduz o erro da Bot API para algo que o usuário entenda."""
    desc, code = (res.get("description") or ""), res.get("error_code")
    low = desc.lower()
    if code == 401:
        return "token inválido (confira o token que o @BotFather enviou)"
    if "chat not found" in low:
        return "Chat ID não encontrado. Envie /start ao bot (ou uma mensagem no grupo) e use “Descobrir”."
    if "blocked" in low or "can't initiate" in low or "kicked" in low:
        return "o bot não pode falar com esse chat. Abra o bot no Telegram e envie /start (ou adicione-o ao grupo)."
    if "not enough rights" in low or "have no rights" in low:
        return "o bot não tem permissão para escrever nesse canal/grupo (torne-o administrador)."
    if code == 429:
        return "limite de mensagens do Telegram atingido; tente de novo em instantes"
    return desc or "erro %s" % code


def _tg_call(token, method, payload=None, timeout=10):
    """Chama a Bot API. Levanta TgError com mensagem em português (sem expor o token)."""
    req = urllib.request.Request("https://api.telegram.org/bot%s/%s" % (token, method),
                                 data=json.dumps(payload or {}).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res = json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            res = json.loads(e.read())
        except ValueError:
            raise TgError("o Telegram respondeu HTTP %d" % e.code)
    except (urllib.error.URLError, OSError, ValueError) as e:
        why = str(getattr(e, "reason", e)).replace(token, "***")
        raise TgError("sem conexão com o Telegram (%s). O servidor precisa de acesso à internet." % why)
    if not res.get("ok"):
        raise TgError(_tg_message(res), retry=(res.get("parameters") or {}).get("retry_after"))
    return res.get("result")


def tg_send(text, cfg=None):
    cfg = cfg or tg_config()
    payload = {"chat_id": cfg["chat_id"], "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    for attempt in range(2):
        try:
            return _tg_call(cfg["token"], "sendMessage", payload)
        except TgError as e:
            if e.retry and attempt == 0 and e.retry <= 60:   # o Telegram pediu para esperar
                time.sleep(e.retry + 1)
                continue
            raise


def _tg_track(err):
    with _tg_lock:
        if err:
            _tg_state["last_error"] = err
        else:
            _tg_state.update(last_ok=int(time.time()), last_error="")
            _tg_state["sent"] += 1


def tg_test():
    """Envia uma mensagem de teste agora. Retorna '' se deu certo ou o erro."""
    try:
        tg_send("✅ <b>NetWatch conectado</b>\nAs notificações estão ativas neste chat.")
        _tg_track("")
        return ""
    except TgError as e:
        _tg_track(str(e))
        return str(e)


def tg_discover(token):
    """Lista as conversas que já falaram com o bot (para descobrir o Chat ID)."""
    token = (token or "").strip() or tg_config()["token"]
    if not _TG_TOKEN_RE.fullmatch(token):
        raise TgError("Informe o token do bot primeiro.")
    chats = {}
    for u in _tg_call(token, "getUpdates", {"limit": 100}) or []:
        for key in ("message", "edited_message", "channel_post", "my_chat_member"):
            c = (u.get(key) or {}).get("chat")
            if c and "id" in c:
                name = c.get("title") or " ".join(p for p in (c.get("first_name"), c.get("last_name")) if p) or c.get("username") or str(c["id"])
                chats[c["id"]] = {"id": str(c["id"]), "type": c.get("type", ""), "name": name}
    if not chats:
        raise TgError("Nenhuma conversa encontrada. Abra o bot no Telegram, envie /start (ou uma mensagem no grupo) e tente de novo.")
    return list(chats.values())


# ---- mensagens
def _h(v):
    return _attr(str(v), quote=False)


def _when(ts):
    return time.strftime("%d/%m %H:%M:%S", time.localtime(ts))


def _fdur(sec):
    sec = max(0, int(sec))
    if sec < 60:
        return "%d s" % sec
    m = sec // 60
    if m < 60:
        return "%d min" % m
    h, m = divmod(m, 60)
    if h < 24:
        return "%d h %d min" % (h, m) if m else "%d h" % h
    d, h = divmod(h, 24)
    return "%d d %d h" % (d, h) if h else "%d d" % d


def _tg_enqueue(ev):
    try:
        _tg_queue.put_nowait(ev)
    except queue.Full:
        log.warning("fila do Telegram cheia: aviso descartado")


def tg_device_event(kind, d, detail, ref):
    """kind 'down' (ref = quando começou) ou 'up' (ref = quanto tempo ficou fora, em segundos)."""
    cfg = tg_config()
    if not cfg["enabled"] or not cfg["on_down" if kind == "down" else "on_up"]:
        return
    who = "%s (%s)" % (_h(d["name"]), _h(d["host"])) if d["name"] != d["host"] else _h(d["host"])
    if kind == "down":
        full = "🔴 <b>Dispositivo offline</b>\n%s\nCategoria: %s\nMotivo: %s\nDesde %s" % (who, _h(d["category"]), _h(detail)[:200], _when(ref))
        short = "%s: %s" % (who, _h(detail)[:80])
    else:
        full = "🟢 <b>Dispositivo voltou</b>\n%s\nCategoria: %s\nFicou fora por %s" % (who, _h(d["category"]), _fdur(ref))
        short = "%s (fora por %s)" % (who, _fdur(ref))
    _tg_enqueue({"kind": "dev_" + kind, "full": full, "short": short})


def tg_port_event(kind, dev, iface, alias, ref):
    """kind 'down' (ref = quando começou) ou 'up' (ref = quanto tempo ficou down, em segundos)."""
    cfg = tg_config()
    if not cfg["enabled"] or not cfg["on_ports"]:
        return
    eq = _h(dev["name"] or dev["host"])
    desc = "\nDescrição: %s" % _h(alias) if alias else ""
    if kind == "down":
        full = "🔴 <b>Porta down</b>: %s\nEquipamento: %s%s\nDesde %s" % (_h(iface), eq, desc, _when(ref))
        short = "%s em %s%s" % (_h(iface), eq, " (%s)" % _h(alias) if alias else "")
    else:
        full = "🟢 <b>Porta voltou</b>: %s\nEquipamento: %s%s\nFicou down por %s" % (_h(iface), eq, desc, _fdur(ref))
        short = "%s em %s (down por %s)" % (_h(iface), eq, _fdur(ref))
    _tg_enqueue({"kind": "port_" + kind, "full": full, "short": short})


def _tg_compose(batch):
    """Junta os avisos do lote em uma ou mais mensagens (limite do Telegram: 4096 caracteres)."""
    if len(batch) <= 3:
        text = "\n\n".join(e["full"] for e in batch)
    else:
        titles = {"dev_down": ("🔴 %d dispositivo offline", "🔴 %d dispositivos offline"),
                  "port_down": ("🔴 %d porta down", "🔴 %d portas down"),
                  "dev_up": ("🟢 %d dispositivo voltou", "🟢 %d dispositivos voltaram"),
                  "port_up": ("🟢 %d porta voltou", "🟢 %d portas voltaram")}
        parts = []
        for kind in ("dev_down", "port_down", "dev_up", "port_up"):
            lines = [e["short"] for e in batch if e["kind"] == kind]
            if lines:
                body = "\n".join("• " + l for l in lines[:TG_MAX_LINES])
                if len(lines) > TG_MAX_LINES:
                    body += "\n… e mais %d" % (len(lines) - TG_MAX_LINES)
                parts.append("<b>%s</b>\n%s" % (titles[kind][len(lines) != 1] % len(lines), body))
        text = "\n\n".join(parts)
    out = []
    while len(text) > 4000:                 # quebra em um limite de linha
        cut = text.rfind("\n", 0, 4000)
        cut = cut if cut > 0 else 4000
        out.append(text[:cut])
        text = text[cut:].lstrip("\n")
    return out + [text]


def tg_worker():
    while True:
        batch = [_tg_queue.get()]
        end = time.monotonic() + TG_BATCH_SECONDS          # espera um instante para agrupar avisos que chegam juntos
        while True:
            left = end - time.monotonic()
            if left <= 0:
                break
            try:
                batch.append(_tg_queue.get(timeout=left))
            except queue.Empty:
                break
        cfg = tg_config()
        if not cfg["enabled"]:
            continue
        for text in _tg_compose(batch):
            try:
                tg_send(text, cfg)
                _tg_track("")
            except TgError as e:
                log.warning("Telegram: falha ao enviar (%s)", e)
                _tg_track(str(e))
                break
            time.sleep(1.1)                                  # o Telegram limita a ~1 mensagem por segundo


# ------------------------------------ estado --------------------------------
def build_state():
    t = int(time.time())
    devices = q("""SELECT * FROM devices ORDER BY
                   CASE status WHEN 'offline' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END, name COLLATE NOCASE""")
    outs = q("""SELECT o.id, o.device_id, d.name, d.host, d.category, o.started, o.ended, o.start_reason, o.end_reason
                FROM outages o JOIN devices d ON d.id=o.device_id ORDER BY o.started DESC LIMIT 300""")
    for o in outs:
        o["duration"] = (o["ended"] or t) - o["started"]
    # disponibilidade das últimas 24 h (a partir do cadastro, se for mais recente) + trechos para a barra
    win0, segs_by = t - 86400, {}
    for o in q("SELECT device_id, started, ended FROM outages WHERE COALESCE(ended, ?) >= ?", (t, win0)):
        s0, e0 = max(o["started"], win0), min(o["ended"] or t, t)
        if e0 > s0:
            segs_by.setdefault(o["device_id"], []).append([s0, e0])
    for d in devices:
        segs, m0 = segs_by.get(d["id"], []), max(win0, d["created"])
        window = max(1, t - m0)
        down = sum(max(0, e - max(s0, m0)) for s0, e in segs)
        d["uptime"] = round(100 * (1 - min(down, window) / window), 2)
        d["outages_24h"], d["monitored_since"] = segs, m0
    registered = {d["host"] for d in devices}
    existing = {c.lower(): c for c in category_names()}
    with _scan_lock:
        found = sorted(scan["found"], key=lambda h: ipaddress.IPv4Address(h["ip"]))
        sc = dict(scan, found=[dict(h, registered=h["ip"] in registered, suggested=suggest_category(h, existing)) for h in found],
                  nmap=bool(nmap_path()), privileged=PRIVILEGED, ports=SCAN_PORTS, port_names=PORT_NAMES)
    counts = {s: sum(1 for d in devices if d["status"] == s) for s in ("online", "offline", "unknown")}
    return {"devices": devices, "outages": outs, "counts": counts, "scan": sc,
            "default_network": DEFAULT_SCAN_NETWORK, "categories": category_names(), "default_category": default_category(), "fails_to_offline": FAILS_TO_OFFLINE,
            "window_from": win0, "window_to": t, "snmp": sn_snapshot(), "telegram": tg_snapshot(), "now": t}


# ------------------------------------- HTTP ---------------------------------
# ---------------------------------- login (código de 4 números) ----------------------------------
_sessions, _sess_lock = {}, threading.Lock()
_login_fails, _login_lock = {}, threading.Lock()
COOKIE = "nw_session"


def session_new():
    now = time.time()
    with _sess_lock:
        for t in [t for t, exp in _sessions.items() if exp < now]:
            del _sessions[t]
        if len(_sessions) >= 200:                       # limite: descarta a mais antiga
            del _sessions[min(_sessions, key=_sessions.get)]
        tok = secrets.token_urlsafe(32)
        _sessions[tok] = now + SESSION_HOURS * 3600
    return tok


def session_valid(tok):
    with _sess_lock:
        exp = _sessions.get(tok or "")
        if exp and exp < time.time():
            del _sessions[tok]
            return False
        return bool(exp)


def session_drop(tok):
    with _sess_lock:
        _sessions.pop(tok or "", None)


def login_attempt(ip, pin):
    """Confere o código. Retorna ('ok', token) | ('bad', tentativas_restantes) | ('locked', segundos).
    Depois de LOGIN_MAX_FAILS erros o IP fica bloqueado (e nem um código certo entra durante o bloqueio)."""
    now, lock_s = time.time(), LOGIN_LOCK_MINUTES * 60
    with _login_lock:
        if len(_login_fails) > 1000:                    # limpeza de registros antigos
            for k in [k for k, f in _login_fails.items() if f["locked_until"] < now and now - f["last"] > lock_s]:
                del _login_fails[k]
        f = _login_fails.setdefault(ip, {"n": 0, "last": now, "locked_until": 0})
        if f["locked_until"] > now:
            return "locked", int(f["locked_until"] - now) + 1
        if now - f["last"] > lock_s:                    # erros antigos não contam
            f["n"] = 0
        if hmac.compare_digest(pin.encode(), PANEL_PIN.encode()):
            del _login_fails[ip]
            return "ok", session_new()
        f["n"], f["last"] = f["n"] + 1, now
        if f["n"] >= LOGIN_MAX_FAILS:
            f["n"], f["locked_until"] = 0, now + lock_s
            log.warning("login: IP %s bloqueado por %d min (%d códigos errados)", ip, LOGIN_LOCK_MINUTES, LOGIN_MAX_FAILS)
            return "locked", int(lock_s)
        log.warning("login: código errado vindo de %s (%d/%d)", ip, f["n"], LOGIN_MAX_FAILS)
        return "bad", LOGIN_MAX_FAILS - f["n"]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silencia o log de cada requisição
        pass

    def send_body(self, body, ctype, code=200, headers=()):
        """Envia a resposta comprimida (gzip) quando o navegador aceita: a lista de centenas de
        dispositivos vai de ~100 KB para ~10 KB a cada atualização."""
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        for k, v in headers:
            self.send_header(k, v)
        if len(body) > 1024 and "gzip" in (self.headers.get("Accept-Encoding") or ""):
            body = gzip.compress(body, 5)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, code=200, headers=()):
        self.send_body(json.dumps(obj).encode(), "application/json; charset=utf-8", code, headers)

    def token(self):
        c = SimpleCookie(self.headers.get("Cookie") or "").get(COOKIE)
        return c.value if c else ""

    def authed(self):
        return not PANEL_PIN or session_valid(self.token())

    def cookie(self, value, max_age):
        # HttpOnly: o JavaScript não lê; SameSite=Strict: outros sites não conseguem usar a sessão
        return ("Set-Cookie", "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d" % (COOKIE, value, max_age))

    def read_json(self):
        # Exigir JSON bloqueia formulários de outros sites (CSRF): o navegador pediria preflight.
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            raise ValueError("Content-Type deve ser application/json.")
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            raise ValueError("Corpo grande demais.")
        return json.loads(self.rfile.read(n) or b"{}")

    def handle_any(self, method):
        try:
            path = self.path.split("?")[0]
            if method == "GET" and path == "/":   # sem sessão válida: mostra a tela do código
                page = render_page() if self.authed() else render_login()
                return self.send_body(page.encode(), "text/html; charset=utf-8")
            if method == "POST" and path == "/api/login":
                b = self.read_json()
                pin = str(b.get("pin") or "")
                if not PANEL_PIN:
                    return self.send_json({"ok": True})
                if not re.fullmatch(r"\d{4}", pin):
                    return self.send_json({"error": "Digite os 4 números do código."}, 400)
                res, val = login_attempt(self.client_address[0], pin)
                if res == "ok":
                    return self.send_json({"ok": True}, headers=[self.cookie(val, SESSION_HOURS * 3600)])
                if res == "locked":
                    return self.send_json({"error": "Muitas tentativas. Aguarde para tentar de novo.", "retry": val}, 429)
                time.sleep(0.3)   # atrasa quem tenta adivinhar
                return self.send_json({"error": "Código incorreto. Restam %d tentativa(s)." % val, "left": val}, 401)
            if not self.authed():
                return self.send_json({"error": "Não autenticado."}, 401)
            if method == "POST" and path == "/api/logout":
                session_drop(self.token())
                return self.send_json({"ok": True}, headers=[self.cookie("", 0)])
            if method == "GET" and path == "/api/state":
                return self.send_json(build_state())

            if method == "POST" and path == "/api/devices":
                b = self.read_json()
                new_id = add_device(b.get("name"), b.get("host"), b.get("category"))
                threading.Thread(target=check, args=(new_id,), daemon=True).start()
                return self.send_json({"id": new_id}, 201)

            if method == "POST" and path == "/api/devices/bulk":
                added, skipped = 0, []
                b = self.read_json()
                cat = parse_category(b.get("category"))  # valida antes de cadastrar qualquer um
                for it in b.get("devices", [])[:1024]:
                    try:
                        new_id = add_device(it.get("name"), it.get("host"), it.get("category") or cat,
                                            it.get("mac"), it.get("vendor"))
                        added += 1
                    except ValueError as e:
                        skipped.append("%s: %s" % (it.get("host"), e))
                _wake.set()  # o monitor confere todos os novos de uma vez (sem criar uma thread por dispositivo)
                return self.send_json({"added": added, "skipped": skipped})

            if method == "POST" and path == "/api/devices/batch":   # ações em massa: mudar categoria / excluir
                b = self.read_json()
                try:
                    ids = [int(i) for i in b.get("ids", [])[:900]]
                except (TypeError, ValueError):
                    raise ValueError("Lista de dispositivos inválida.")
                if not ids:
                    raise ValueError("Nenhum dispositivo selecionado.")
                marks = ",".join("?" * len(ids))
                if b.get("action") == "category":
                    x("UPDATE devices SET category=? WHERE id IN (%s)" % marks, [parse_category(b.get("category"))] + ids)
                elif b.get("action") == "delete":
                    x("DELETE FROM devices WHERE id IN (%s)" % marks, ids)
                else:
                    raise ValueError("Ação inválida.")
                return self.send_json({"ok": True, "count": len(ids)})
            if method == "POST" and path == "/api/telegram/config":
                tg_save(self.read_json())
                err = tg_test() if tg_config()["enabled"] else ""    # ativou: já manda uma mensagem de teste
                return self.send_json({"ok": not err, "error": err})
            if method == "POST" and path == "/api/telegram/chats":
                return self.send_json({"chats": tg_discover(self.read_json().get("token"))})
            if method == "POST" and path == "/api/snmp/devices":
                dev_id, err = snd_save(self.read_json())
                return self.send_json({"ok": not err, "error": err, "id": dev_id}, 201)
            m = re.fullmatch(r"/api/snmp/devices/(\d+)(/poll)?", path)
            if m and method == "PATCH" and not m.group(2):
                dev_id, err = snd_save(self.read_json(), int(m.group(1)))
                return self.send_json({"ok": not err, "error": err, "id": dev_id})
            if m and method == "DELETE" and not m.group(2):
                if not snd_delete(int(m.group(1))):
                    return self.send_json({"error": "Equipamento não encontrado."}, 404)
                return self.send_json({"ok": True})
            if m and method == "POST" and m.group(2):
                dev = snd_get(int(m.group(1)))
                if not dev:
                    return self.send_json({"error": "Equipamento não encontrado."}, 404)
                err = sn_poll(dev)
                return self.send_json({"ok": not err, "error": err})
            if method == "POST" and path == "/api/categories":
                return self.send_json({"name": add_category(self.read_json().get("name"))}, 201)
            if method == "POST" and path == "/api/categories/rename":
                b = self.read_json()
                return self.send_json({"name": rename_category(b.get("name"), b.get("new_name"))})
            if method == "POST" and path == "/api/categories/delete":
                return self.send_json({"moved": delete_category(self.read_json().get("name"))})

            m = re.fullmatch(r"/api/devices/(\d+)(/check)?", path)
            if m and method == "PATCH" and not m.group(2):  # edita nome e/ou categoria
                b, dev_id = self.read_json(), int(m.group(1))
                dev = q("SELECT host FROM devices WHERE id=?", (dev_id,))
                if not dev:
                    return self.send_json({"error": "Dispositivo não encontrado."}, 404)
                cat = parse_category(b.get("category")) if "category" in b else None   # valida tudo antes de gravar
                name = clean_device_name(b.get("name"), dev[0]["host"]) if "name" in b else None
                mac = parse_mac_input(b.get("mac")) if "mac" in b else None
                if cat is not None:
                    x("UPDATE devices SET category=? WHERE id=?", (cat, dev_id))
                if name is not None:
                    x("UPDATE devices SET name=? WHERE id=?", (name, dev_id))
                if mac is not None:   # vazio = esquece o MAC (será aprendido de novo no próximo ping)
                    x("UPDATE devices SET mac=?, vendor=? WHERE id=?", (mac, mac_vendor(mac) if mac else "", dev_id))
                return self.send_json({"ok": True, "name": name, "category": cat})
            if m and method == "DELETE" and not m.group(2):
                x("DELETE FROM devices WHERE id=?", (int(m.group(1)),))
                return self.send_json({"ok": True})
            if m and method == "POST" and m.group(2):
                check(int(m.group(1)), retry=False)  # verificação manual: 1 ping só
                return self.send_json({"ok": True})

            if method == "POST" and path == "/api/scan":
                b = self.read_json()
                if not start_scan(b.get("network"), bool(b.get("deep"))):
                    return self.send_json({"error": "Já existe uma varredura em andamento."}, 409)
                return self.send_json({"ok": True}, 202)

            self.send_json({"error": "Rota não encontrada."}, 404)
        except (ValueError, json.JSONDecodeError) as e:
            self.send_json({"error": str(e)}, 400)
        except Exception as e:
            log.exception("erro em %s %s", method, self.path)
            self.send_json({"error": "Erro interno: %s" % e}, 500)

    def do_GET(self): self.handle_any("GET")
    def do_POST(self): self.handle_any("POST")
    def do_PATCH(self): self.handle_any("PATCH")
    def do_DELETE(self): self.handle_any("DELETE")


# ------------------------------------ página --------------------------------
PAGE = r"""<!doctype html>
<html lang="pt-BR" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>NetWatch</title>
<!--FAVICON-->
<script>try{document.documentElement.dataset.theme=localStorage.getItem('nw_theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light')}catch(e){}</script>
<style>
  :root{
    --ink:#15202B; --mute:#5B6B7B; --faint:#8A97A5; --paper:#F1F4F7; --sheet:#FFFFFF; --sheet-2:#F7F9FB; --field:#FFFFFF;
    --line:#E0E6EC; --line-2:#EBEEF2; --up:#0E9F6E; --down:#E03E45; --wait:#B7791F; --dim:#C6CFD8;
    --down-soft:#FDECEC; --wait-soft:#FBF1D9; --up-soft:#DDF3EA; --track:#A6DCC6;
    --accent:#2350D8; --accent-soft:#E7EDFC; --in:#2350D8; --out:#D9822B; --shadow:0 1px 2px rgba(16,24,40,.06);
    --cols:34px 142px minmax(190px,1fr) 116px 76px 190px 156px 108px;
    --sans:"Segoe UI Variable","Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif;
    --mono:ui-monospace,"Cascadia Mono",Consolas,Menlo,monospace;
  }
  :root[data-theme=dark]{
    --ink:#E6EDF3; --mute:#9AA9B8; --faint:#6F7E8D; --paper:#0F151B; --sheet:#171F27; --sheet-2:#1B2530; --field:#1D2833;
    --line:#293541; --line-2:#222C36; --up:#3CCB8F; --down:#FF6B72; --wait:#E8B04A; --dim:#36434F;
    --down-soft:#3A1E23; --wait-soft:#3A3015; --up-soft:#15392C; --track:#1E6B50;
    --accent:#7B9BFF; --accent-soft:#1E2B4F; --in:#7B9BFF; --out:#F0A45D; --shadow:none; color-scheme:dark;
  }
  *{box-sizing:border-box}
  [hidden]{display:none!important}
  html{background:var(--paper)}
  body{margin:0;color:var(--ink);font:14px/1.45 var(--sans);font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased;min-height:100vh}
  button,input,select,textarea{font:inherit;color:inherit}
  :focus-visible{outline:2px solid var(--accent);outline-offset:2px}
  h1,h2,h3{margin:0}
  .mute{color:var(--mute)} .grow{flex:1}
  .top,.tabs,main{max-width:1480px;margin:0 auto;padding-left:24px;padding-right:24px}

  /* ---------- Cabeçalho ---------- */
  .top{display:flex;align-items:center;gap:14px;padding-top:16px;padding-bottom:12px;flex-wrap:wrap}
  .brand{display:flex;align-items:center;gap:12px;margin-right:8px}
  .logo{height:60px;width:auto;max-width:180px;object-fit:contain;display:block}
  .brand h1{font-size:21px;font-weight:700;letter-spacing:-.02em;line-height:1.1}
  .brand small{display:block;color:var(--mute);font-size:12px}
  .stats{display:flex;gap:8px;flex-wrap:wrap}
  .stat{display:inline-flex;align-items:center;gap:8px;padding:6px 13px;border-radius:999px;border:1px solid var(--line);background:var(--sheet);cursor:pointer;color:var(--mute);box-shadow:var(--shadow)}
  .stat b{font-size:16px;color:var(--ink)} .stat:hover{border-color:var(--faint)}
  .d{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--dim)} .d.up{background:var(--up)} .d.down{background:var(--down)} .d.wait{background:#E8B04A}
  .live{font-size:12px;color:var(--faint)} .live.bad{color:var(--down);font-weight:600}

  .btn{display:inline-flex;align-items:center;gap:7px;padding:7px 13px;border-radius:8px;border:1px solid var(--line);background:var(--sheet);font-weight:600;cursor:pointer;box-shadow:var(--shadow);white-space:nowrap}
  .btn:hover{border-color:var(--faint)} .btn:disabled{opacity:.5;cursor:not-allowed}
  .btn.p{background:var(--accent);border-color:var(--accent);color:#fff} .btn.p:hover{filter:brightness(1.08)}
  :root[data-theme=dark] .btn.p{color:#0B1220}
  .btn.danger{color:var(--down)}
  .ib{width:30px;height:30px;display:inline-grid;place-items:center;border:0;border-radius:7px;background:none;color:var(--mute);cursor:pointer;padding:0}
  .ib:hover{background:var(--accent-soft);color:var(--accent)} .ib.danger:hover{background:var(--down-soft);color:var(--down)}
  .ib.lg{width:36px;height:36px;border:1px solid var(--line);background:var(--sheet);position:relative}
  .ib.lg.dot-on::after,.ib.lg.dot-err::after{content:"";position:absolute;top:5px;right:5px;width:9px;height:9px;border-radius:50%;border:2px solid var(--sheet)}
  .ib.lg.dot-on::after{background:var(--up)} .ib.lg.dot-err::after{background:var(--down)}
  .link{background:none;border:0;padding:0;color:var(--accent);text-decoration:underline;text-underline-offset:3px;cursor:pointer}
  .link.d{color:var(--down)}
  input,select,textarea{background:var(--field);border:1px solid var(--line);border-radius:8px;padding:7px 10px}
  input[type=checkbox]{width:16px;height:16px;padding:0;accent-color:var(--accent);cursor:pointer}

  /* ---------- Abas ---------- */
  .tabs{display:flex;gap:2px;border-bottom:1px solid var(--line);overflow-x:auto}
  .tabs button{border:0;border-radius:0;background:none;color:var(--mute);padding:10px 16px;margin-bottom:-1px;border-bottom:3px solid transparent;white-space:nowrap;font-weight:600;cursor:pointer}
  .tabs button:hover{color:var(--ink)} .tabs button[aria-selected=true]{color:var(--ink);border-bottom-color:var(--accent)}
  .cnt{display:inline-block;min-width:22px;padding:0 7px;margin-left:8px;border-radius:11px;background:var(--line);color:var(--ink);font-size:12px;font-weight:600;text-align:center}
  .cnt.bad{background:var(--down);color:#fff} .cnt.wait{background:var(--wait-soft);color:var(--wait)}
  main{padding-top:16px;padding-bottom:90px}

  /* ---------- Mapa da rede (um quadrado por dispositivo) ---------- */
  .fleetwrap{background:var(--sheet);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:14px;box-shadow:var(--shadow)}
  .fleethead{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
  .fleethead h2{font-size:15px}
  .legend{margin-left:auto;display:flex;gap:14px;font-size:12px;color:var(--mute)}
  .legend span{display:inline-flex;align-items:center;gap:6px}
  .fleet{display:flex;flex-wrap:wrap;gap:4px;margin-top:12px;max-height:150px;overflow-y:auto;padding:1px}
  .cell{width:16px;height:16px;border-radius:4px;border:0;padding:0;cursor:pointer;background:var(--up);opacity:.5;transition:transform .08s}
  .cell:hover{opacity:1;transform:scale(1.25)}
  .cell.down{background:var(--down);opacity:1} .cell.wait{background:#E8B04A;opacity:1} .cell.unk{background:var(--dim);opacity:1}
  .cell.dim{opacity:.13} .cell.dim.down{opacity:.35}
  .cell:focus-visible{outline-offset:1px}

  /* ---------- Barra de filtros (fixa ao rolar) ---------- */
  .sticky{position:sticky;top:0;z-index:8;background:var(--paper);padding-top:2px}
  .toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:6px 0 10px}
  .search{position:relative;flex:1 1 260px;max-width:440px}
  .search svg{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--faint);pointer-events:none}
  .search input{width:100%;padding-left:34px;padding-right:34px}
  .search kbd{position:absolute;right:9px;top:50%;transform:translateY(-50%);font:12px var(--mono);color:var(--faint);border:1px solid var(--line);border-radius:5px;padding:0 6px;background:var(--sheet-2);pointer-events:none}
  .seg{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:var(--sheet)}
  .seg button{border:0;background:none;padding:7px 12px;cursor:pointer;color:var(--mute);font-weight:600;white-space:nowrap}
  .seg button+button{border-left:1px solid var(--line)}
  .seg button.on{background:var(--ink);color:var(--paper)} .seg span{opacity:.7;margin-left:6px;font-weight:400}
  .cats{display:flex;gap:6px;overflow-x:auto;padding:0 0 10px;scrollbar-width:thin}
  .cats button{border:1px solid var(--line);background:var(--sheet);border-radius:999px;padding:4px 12px;cursor:pointer;white-space:nowrap;font-weight:600;color:var(--mute)}
  .cats button:hover{border-color:var(--faint)} .cats button.on{background:var(--accent);border-color:var(--accent);color:#fff}
  :root[data-theme=dark] .cats button.on{color:#0B1220}
  .cats .n{font-weight:400;opacity:.75;margin-left:6px}
  .cats .bad{background:var(--down);color:#fff;border-radius:9px;padding:0 6px;margin-left:6px;font-size:12px;font-weight:600;opacity:1}

  /* ---------- Lista de dispositivos ---------- */
  .row{display:grid;grid-template-columns:var(--cols);gap:12px;align-items:center;padding:0 14px;min-height:var(--rh,56px)}
  .colhead{--rh:38px;background:var(--sheet-2);border:1px solid var(--line);border-radius:12px 12px 0 0;font-size:12px;font-weight:600;color:var(--mute)}
  .sortbtn{display:inline-flex;align-items:center;gap:5px;background:none;border:0;padding:0;color:inherit;font-weight:600;font-size:12px;cursor:pointer}
  .sortbtn:hover,.sortbtn.on{color:var(--ink)} .arr{font-size:8px}
  .colhead .k-name{display:flex;gap:16px}
  .list{--rh:56px;background:var(--sheet);border:1px solid var(--line);border-top:0;border-radius:0 0 12px 12px;box-shadow:var(--shadow)}
  .list.compact{--rh:38px}
  .item{border-bottom:1px solid var(--line-2);content-visibility:auto;contain-intrinsic-size:auto var(--rh)}
  .item:last-child{border-bottom:0}
  .item .row:hover{background:var(--sheet-2)}
  .row.st-down{background:linear-gradient(90deg,var(--down-soft),transparent 70%);box-shadow:inset 3px 0 0 var(--down)}
  .row.st-wait{background:linear-gradient(90deg,var(--wait-soft),transparent 60%);box-shadow:inset 3px 0 0 #E8B04A}
  .row.selected{background:var(--accent-soft)!important}
  .k-status .pill{display:inline-flex;align-items:center;gap:7px;font-weight:600;font-size:13px;white-space:nowrap}
  .pill i{width:9px;height:9px;border-radius:50%;background:currentColor;flex:none}
  .pill.up{color:var(--up)} .pill.down{color:var(--down)} .pill.wait{color:var(--wait)} .pill.unk{color:var(--faint)}
  .namebtn{display:flex;flex-direction:column;min-width:0;width:100%;background:none;border:0;padding:0;text-align:left;cursor:pointer}
  .nm{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .host{font:12px var(--mono);color:var(--mute);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .why{font:11.5px var(--mono);color:var(--wait);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%} .st-down .why{color:var(--down)}
  .compact .namebtn{flex-direction:row;align-items:baseline;gap:12px} .compact .why{flex:1;min-width:0}
  .chip{display:inline-block;max-width:100%;padding:1px 9px;border-radius:999px;background:var(--sheet-2);border:1px solid var(--line);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle}
  .k-lat{font-size:13px;text-align:right} .k-since{font-size:12.5px;color:var(--mute)}
  .k-bar{display:flex;align-items:center;gap:8px}
  .track{position:relative;flex:1;height:10px;border-radius:3px;overflow:hidden;background:var(--track);min-width:40px}
  .track .pre{position:absolute;inset:0 auto 0 0;background:repeating-linear-gradient(135deg,var(--line) 0 4px,var(--line-2) 4px 8px)}
  .track .tseg{position:absolute;top:0;bottom:0;min-width:3px;background:var(--down)}
  .pct{width:46px;text-align:right;font-size:12px;color:var(--mute)}
  .k-act{display:flex;justify-content:flex-end;gap:2px}
  .detail{padding:12px 14px 14px 60px;background:var(--sheet-2);border-top:1px dashed var(--line)}
  .detail dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px 28px;margin:0}
  .detail dt{font-size:11px;color:var(--faint);margin-bottom:1px} .detail dd{margin:0;font:12.5px var(--mono);overflow-wrap:anywhere}
  @media (prefers-reduced-motion:no-preference){.row.flash{animation:flash 1.6s ease-out}}
  @keyframes flash{0%,35%{background:var(--accent-soft)}100%{background:transparent}}
  .empty{padding:44px 24px;text-align:center;color:var(--mute)}
  .empty strong{display:block;color:var(--ink);font-size:16px;margin-bottom:6px}
  .empty .btn{margin:14px 4px 0}
  .sheet{background:var(--sheet);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow);overflow-x:auto}

  /* ---------- Portas SNMP (equipamentos) ---------- */
  .eq-info{display:flex;gap:14px 24px;flex-wrap:wrap;align-items:center;padding:14px 18px;margin-bottom:14px;overflow:visible}
  .eq-info .kv small{display:block;font-size:11px;color:var(--faint)} .eq-info .kv b{font-size:15px}
  .eq-info .pill,.pcard .pill{display:inline-flex;align-items:center;gap:7px;font-weight:600;font-size:13px;white-space:nowrap}
  .eq-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:14px;margin-bottom:26px}
  .pcard{background:var(--sheet);border:1px solid var(--line);border-left:4px solid var(--up);border-radius:12px;padding:16px 18px;box-shadow:var(--shadow)}
  .pcard.down{border-left-color:var(--down);background:linear-gradient(100deg,var(--down-soft),var(--sheet) 60%)}
  .pcard.disabled,.pcard.missing,.pcard.unknown{border-left-color:var(--dim)} .pcard.stale{opacity:.6}
  .phead{display:flex;align-items:center;justify-content:space-between;gap:10px}
  .phead h3{font:700 19px var(--mono);letter-spacing:-.01em}
  .palias{margin:5px 0 0;font-size:13px;font-weight:600;color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap} .palias.none{font-weight:400;font-style:italic;color:var(--faint)}
  td .palias{display:block;font-weight:400;font-size:12px;color:var(--mute);margin-top:1px;max-width:260px}
  .pmeta{display:flex;gap:18px;flex-wrap:wrap;margin:6px 0 2px;font-size:12.5px;color:var(--mute)} .pmeta b{color:var(--ink);font-weight:600}
  .rates{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:14px 0 10px}
  .rate small{color:var(--mute);font-size:12px} .rate b{display:block;font-size:22px;letter-spacing:-.02em;margin:1px 0 6px}
  .ubar{height:5px;background:var(--line-2);border-radius:3px;overflow:hidden} .ubar i{display:block;height:100%;border-radius:3px}
  .spark{width:100%;height:54px;display:block;margin-top:6px;background:var(--sheet-2);border-radius:6px}
  .spark polyline{fill:none;stroke-width:1.6;vector-effect:non-scaling-stroke;stroke-linejoin:round} .ln-in{stroke:var(--in)} .ln-out{stroke:var(--out)}
  .spark-note{display:flex;justify-content:space-between;font-size:11.5px;color:var(--faint);margin-top:4px}
  .spark-note .lg-in::before,.spark-note .lg-out::before{content:"";display:inline-block;width:10px;height:3px;border-radius:2px;margin-right:5px;vertical-align:middle}
  .lg-in::before{background:var(--in)} .lg-out::before{background:var(--out)} .spark-note span+span{margin-left:12px}
  .perr{display:flex;gap:18px;margin-top:10px;padding-top:10px;border-top:1px solid var(--line-2);font-size:12.5px;color:var(--mute)} .perr b{color:var(--ink)} .perr b.bad{color:var(--down)}
  .eq-h{font-size:15px;margin:8px 0 10px} .eq{margin-bottom:22px}
  .cmd{display:inline-block;text-align:left;margin:16px 0 0;padding:12px 16px;background:var(--sheet-2);border:1px solid var(--line);border-radius:8px;font:12.5px/1.6 var(--mono);color:var(--ink);white-space:pre-wrap}

  /* ---------- Ações em massa ---------- */
  .bulk{position:fixed;left:50%;bottom:20px;transform:translateX(-50%);z-index:30;display:flex;gap:10px;align-items:center;flex-wrap:wrap;
    padding:10px 14px;background:var(--ink);color:var(--paper);border-radius:12px;box-shadow:0 12px 34px rgba(0,0,0,.35);max-width:calc(100vw - 20px)}
  .bulk .btn{box-shadow:none;background:var(--sheet);color:var(--ink);border-color:transparent} .bulk .btn.danger{color:var(--down)} .bulk select{background:var(--sheet);color:var(--ink)}

  /* ---------- Tabelas (varredura, histórico, categorias) ---------- */
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:10px 16px;border-bottom:1px solid var(--line-2);vertical-align:middle}
  th{font-size:12px;color:var(--mute);background:var(--sheet-2);font-weight:600} tr:last-child td{border-bottom:0}
  td .host{display:block}
  .tag{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;background:var(--sheet-2);border:1px solid var(--line);color:var(--mute)}
  .tag.down{background:var(--down-soft);color:var(--down);border-color:transparent} .tag.up{background:var(--up-soft);color:var(--up);border-color:transparent}
  .txt-down{color:var(--down)}
  .detail-l{display:block;margin-top:3px;font:12px/1.35 var(--mono);color:var(--mute);overflow-wrap:anywhere;max-width:480px}
  .ptag{display:inline-block;padding:1px 8px;margin:0 4px 3px 0;border-radius:999px;background:var(--up-soft);color:var(--up);font-size:12px;font-weight:600;text-decoration:none}
  a.ptag:hover{text-decoration:underline}
  select.rowcat{padding:3px 6px;font-size:13px}
  .panel-bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
  .panel-bar input[type=search],.panel-bar input[type=text]{min-width:260px}
  .panel-bar label{display:inline-flex;gap:7px;align-items:center;color:var(--mute)}
  .hint{margin:0 0 12px;color:var(--mute);font-size:13px} .hint code{background:var(--line-2);padding:1px 6px;border-radius:4px}
  progress{width:100%;height:10px;accent-color:var(--accent)}
  .note{padding:12px 16px;color:var(--wait)}

  /* ---------- Diálogos e aviso ---------- */
  dialog{border:0;border-radius:14px;padding:0;width:min(520px,calc(100vw - 28px));color:var(--ink);background:var(--sheet);box-shadow:0 24px 70px rgba(0,0,0,.4)}
  dialog::backdrop{background:rgba(10,16,24,.55)}
  .dlg{padding:22px;display:grid;gap:14px} .dlg h3{font-size:18px}
  .dlg label{display:grid;gap:6px;font-weight:600;font-size:13px} .dlg label small{font-weight:400;color:var(--mute)}
  .dlg input,.dlg select,.dlg textarea{width:100%} .dlg input[readonly]{background:var(--sheet-2);color:var(--mute)}
  .dlg-row{display:flex;gap:8px} .dlg-row input{flex:1;min-width:0}
  .dlg-actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap}
  .dlg .chk{display:flex;align-items:center;gap:9px;font-weight:500;font-size:14px}
  .dlg input[type=checkbox]{width:16px;height:16px;flex:none}
  .dlg fieldset{border:1px solid var(--line);border-radius:10px;padding:10px 14px 12px;margin:0;display:grid;gap:9px} .dlg legend{font-size:13px;font-weight:600;padding:0 6px}
  .chatpick{display:flex;flex-wrap:wrap;gap:8px} .chatpick button{border:1px solid var(--line);background:var(--sheet-2);border-radius:999px;padding:5px 12px;cursor:pointer;font-size:13px}
  .chatpick button:hover{border-color:var(--accent);color:var(--accent)} .chatpick small{color:var(--faint);margin-left:6px}
  .how{font-size:13px;color:var(--mute)} .how summary{cursor:pointer;font-weight:600} .how ol{margin:8px 0 0;padding-left:20px;line-height:1.6}
  .form-error{margin:0;color:var(--down);font-size:13px;min-height:1.3em}
  .dlg .sheet{max-height:48vh;overflow-y:auto}
  #msg{position:fixed;bottom:20px;right:20px;z-index:50;background:var(--ink);color:var(--paper);padding:10px 16px;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.3);max-width:min(420px,calc(100vw - 32px))}
  #msg.err{background:var(--down);color:#fff}

  /* ---------- Telas menores ---------- */
  @media (max-width:1180px){:root{--cols:34px 142px minmax(160px,1fr) 100px 72px 150px 108px}.k-since{display:none}}
  @media (max-width:900px){:root{--cols:30px 140px minmax(130px,1fr) 70px 100px}.k-cat,.k-bar{display:none}.detail{padding-left:16px}}
  @media (max-width:600px){:root{--cols:28px 116px 1fr 96px}.k-lat{display:none}.top,.tabs,main{padding-left:14px;padding-right:14px}.search{max-width:none;flex-basis:100%}.legend{margin-left:0}
    .sticky{position:static}.top{gap:10px}.brand{flex:1}.stats{order:5;width:100%}.live{display:none}#btn-add .lbl{display:none}#btn-add{padding:8px 10px}.search kbd{display:none}
    .toolbar .seg{width:100%}.toolbar .seg button{flex:1;padding:7px 4px}.toolbar .seg span{display:none}#msg{left:12px;right:12px;bottom:84px}}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><!--LOGO--><div><h1>NetWatch</h1><small>Monitoramento de rede</small></div></div>
  <div class="stats" id="stats"></div>
  <span class="grow"></span>
  <span class="live" id="live" role="status"></span>
  <button class="ib lg" id="tgbtn" type="button" aria-label="Notificações no Telegram" title="Notificações no Telegram"><span data-ic="bell" data-s="18"></span></button>
  <button class="ib lg" id="themebtn" type="button" aria-label="Alternar tema claro e escuro"></button>
  <!--LOGOUT-->
  <button class="btn p" id="btn-add" type="button"><span data-ic="plus"></span><span class="lbl">Adicionar dispositivo</span></button>
</header>

<nav class="tabs" role="tablist" aria-label="Seções">
  <button role="tab" id="tab-devices" data-tab="devices" aria-controls="p-devices" aria-selected="true">Dispositivos<span class="cnt" id="c-devices" hidden></span></button>
  <button role="tab" id="tab-scan" data-tab="scan" aria-controls="p-scan" aria-selected="false">Varredura de rede<span class="cnt" id="c-scan" hidden></span></button>
  <button role="tab" id="tab-outages" data-tab="outages" aria-controls="p-outages" aria-selected="false">Histórico de quedas<span class="cnt" id="c-outages" hidden></span></button>
  <button role="tab" id="tab-snmp" data-tab="snmp" aria-controls="p-snmp" aria-selected="false">Portas SNMP<span class="cnt" id="c-snmp" hidden></span></button>
</nav>

<main>
  <!-- ======================= DISPOSITIVOS ======================= -->
  <section id="p-devices" role="tabpanel" aria-labelledby="tab-devices">
    <div class="sheet empty" id="devEmpty" hidden>
      <strong>Nenhum dispositivo monitorado</strong>
      Cadastre um IP ou FQDN, ou deixe a varredura descobrir o que já está ligado na rede.<br>
      <button class="btn p" data-go-add type="button">Adicionar dispositivo</button>
      <button class="btn" data-go="scan" type="button">Varrer a rede</button>
    </div>
    <div id="devMain" hidden>
      <div class="fleetwrap" id="fleetwrap">
        <div class="fleethead">
          <h2>Mapa da rede</h2><span class="mute" id="fleetinfo"></span>
          <div class="legend"><span><i class="d up"></i>online</span><span><i class="d down"></i>offline</span><span><i class="d wait"></i>sem resposta</span><span><i class="d"></i>aguardando</span></div>
        </div>
        <div class="fleet" id="fleet" aria-label="Um quadrado por dispositivo; clique para localizar na lista"></div>
      </div>

      <div class="sticky">
        <div class="toolbar">
          <div class="search"><span data-ic="search" data-s="16"></span><input type="search" id="q" placeholder="Buscar por nome, IP, categoria ou MAC" aria-label="Buscar dispositivos" autocomplete="off"><kbd title="Atalho: tecla /">/</kbd></div>
          <div class="seg" id="seg" role="group" aria-label="Filtrar por status"></div>
          <span class="grow"></span>
          <span class="mute" id="count" aria-live="polite"></span>
          <button class="btn" id="density" type="button" title="Alternar entre lista compacta e confortável"><span data-ic="rows"></span><span id="densitylbl">Compacto</span></button>
          <button class="btn" id="catmanage" type="button">Categorias</button>
        </div>
        <div class="cats" id="cats" aria-label="Filtrar por categoria"></div>
        <div class="row colhead" id="colhead">
          <div class="k-chk"><input type="checkbox" id="selall" aria-label="Selecionar todos os exibidos"></div>
          <div class="k-status"><button class="sortbtn" data-sort="status" type="button">Status<span class="arr"></span></button></div>
          <div class="k-name"><button class="sortbtn" data-sort="name" type="button">Dispositivo<span class="arr"></span></button><button class="sortbtn" data-sort="host" type="button">IP<span class="arr"></span></button></div>
          <div class="k-cat"><button class="sortbtn" data-sort="category" type="button">Categoria<span class="arr"></span></button></div>
          <div class="k-lat"><button class="sortbtn" data-sort="latency" type="button">Latência<span class="arr"></span></button></div>
          <div class="k-bar"><button class="sortbtn" data-sort="uptime" type="button">Últimas 24 horas<span class="arr"></span></button></div>
          <div class="k-since"><button class="sortbtn" data-sort="since" type="button">Tempo no estado<span class="arr"></span></button></div>
          <div class="k-act"></div>
        </div>
      </div>
      <div class="list" id="list"></div>
      <div class="sheet empty" id="listEmpty" hidden style="border-radius:0 0 12px 12px;border-top:0"><strong>Nenhum dispositivo com esses filtros</strong>
        <button class="btn" id="clearfilters" type="button">Limpar filtros</button></div>
    </div>
  </section>

  <!-- ======================= VARREDURA ======================= -->
  <section id="p-scan" role="tabpanel" aria-labelledby="tab-scan" hidden>
    <form id="scanform" class="panel-bar">
      <input type="text" name="network" id="network" placeholder="Rede, ex.: 192.168.2.0/24" maxlength="200" required aria-label="Rede a varrer">
      <button class="btn p" id="scanbtn">Iniciar varredura</button>
      <label id="deeplbl" hidden title="Testa portas em todos os endereços da rede, não só nos que respondem ping. Demora mais."><input type="checkbox" id="deep"> Procurar também quem bloqueia ping (mais lento)</label>
      <span class="grow"></span>
      <label>Categoria padrão dos encontrados <select id="bulkcat"></select></label>
    </form>
    <p class="hint" id="scanhint"></p>
    <div class="sheet" id="scan"></div>
  </section>

  <!-- ======================= HISTÓRICO ======================= -->
  <section id="p-outages" role="tabpanel" aria-labelledby="tab-outages" hidden>
    <div class="panel-bar">
      <div class="search"><span data-ic="search" data-s="16"></span><input type="search" id="oq" placeholder="Filtrar por nome, IP ou categoria" aria-label="Filtrar histórico" autocomplete="off"></div>
      <label><input type="checkbox" id="oopen"> Somente quedas em andamento</label>
      <span class="grow"></span><span class="mute" id="ocount"></span>
    </div>
    <div class="sheet" id="outages"></div>
  </section>

  <!-- ======================= PORTAS SNMP ======================= -->
  <section id="p-snmp" role="tabpanel" aria-labelledby="tab-snmp" hidden>
    <div class="panel-bar"><button class="btn p" data-eq="add" type="button"><span data-ic="plus"></span>Adicionar equipamento</button><span class="grow"></span><span class="mute" id="eqcount"></span></div>
    <div id="eqbody"></div>
  </section>
</main>

<div class="bulk" id="bulk" hidden role="region" aria-label="Ações para os itens selecionados">
  <b id="bulkn"></b>
  <select id="selcat" aria-label="Nova categoria"></select>
  <button class="btn" id="bulkapply" type="button">Mudar categoria</button>
  <button class="btn danger" id="bulkdel" type="button">Excluir</button>
  <button class="btn" id="bulkclear" type="button">Limpar seleção</button>
</div>

<dialog id="devdlg" aria-labelledby="devdlg-t"><form class="dlg" id="devform" novalidate>
  <h3 id="devdlg-t">Adicionar dispositivo</h3>
  <label>Nome <small>Opcional. Se vazio, usamos o endereço.</small><input id="devname" maxlength="100" autocomplete="off" placeholder="Ex.: Câmera da recepção"></label>
  <label>Endereço <small id="devhost-help">IPv4 ou nome completo (FQDN).</small><input id="devhost" maxlength="253" autocomplete="off" placeholder="192.168.2.1 ou gateway.empresa.com.br" required></label>
  <label>Categoria <select id="devcat"></select></label>
  <label id="devmacrow" hidden>MAC conhecido <small>Confirma que quem responde é o mesmo equipamento (rede local, Linux). Apague para aprender de novo.</small><input id="devmac" maxlength="17" autocomplete="off" placeholder="aa:bb:cc:dd:ee:ff"></label>
  <p class="form-error" id="deverr" role="alert"></p>
  <div class="dlg-actions">
    <button type="button" class="btn" id="devcancel">Cancelar</button>
    <button type="button" class="btn" id="devmore">Adicionar e novo</button>
    <button class="btn p" id="devsave">Adicionar</button>
  </div>
</form></dialog>

<dialog id="catdlg" aria-labelledby="catdlg-t"><div class="dlg">
  <h3 id="catdlg-t">Categorias</h3>
  <form id="catform" class="dlg-row"><input id="catname" placeholder="Nova categoria, ex.: Impressoras" maxlength="40" required aria-label="Nome da nova categoria"><button class="btn p">Adicionar categoria</button></form>
  <div class="sheet" id="catlist"></div>
  <div class="dlg-actions"><button type="button" class="btn" id="catclose">Fechar</button></div>
</div></dialog>

<dialog id="tgdlg" aria-labelledby="tgdlg-t"><form class="dlg" id="tgform" novalidate>
  <h3 id="tgdlg-t">Notificações no Telegram</h3>
  <label class="chk"><input type="checkbox" id="tgon"> Enviar notificações pelo Telegram</label>
  <label>Token do bot <small>Criado no @BotFather. Fica guardado só no servidor.</small><input id="tgtoken" type="password" maxlength="80" autocomplete="new-password" placeholder="123456789:AAE…"></label>
  <label>Chat ID <small>Sua conversa, um grupo (começa com -) ou um canal (@nome).</small>
    <span class="dlg-row"><input id="tgchat" maxlength="40" autocomplete="off" placeholder="123456789"><button type="button" class="btn" id="tgfind">Descobrir</button></span></label>
  <div class="chatpick" id="tgchats"></div>
  <fieldset><legend>Avisar quando</legend>
    <label class="chk"><input type="checkbox" id="tgdown"> um dispositivo ficar offline</label>
    <label class="chk"><input type="checkbox" id="tgup"> um dispositivo voltar (com o tempo que ficou fora)</label>
    <label class="chk"><input type="checkbox" id="tgports"> uma porta SNMP cair ou voltar</label></fieldset>
  <p class="mute" id="tgstatus" style="margin:0;font-size:13px"></p>
  <details class="how"><summary>Como configurar</summary><ol>
    <li>No Telegram, abra o <b>@BotFather</b>, envie <code>/newbot</code> e copie o <b>token</b>.</li>
    <li>Abra o seu bot e envie <code>/start</code> (para um grupo: adicione o bot e envie uma mensagem).</li>
    <li>Cole o token acima e clique em <b>Descobrir</b> para achar o Chat ID.</li></ol></details>
  <p class="form-error" id="tgerr" role="alert"></p>
  <div class="dlg-actions"><button type="button" class="btn" id="tgcancel">Cancelar</button><button class="btn p" id="tgsave">Salvar e testar</button></div>
</form></dialog>

<dialog id="eqdlg" aria-labelledby="eqdlg-t"><form class="dlg" id="eqform" novalidate>
  <h3 id="eqdlg-t">Adicionar equipamento SNMP</h3>
  <label>Nome <small>Como aparece na aba. Se vazio, usamos o nome que o equipamento informa.</small><input id="eqname" maxlength="60" autocomplete="off" placeholder="Ex.: Roteador da matriz"></label>
  <label>IP do equipamento<input id="eqhost" maxlength="253" autocomplete="off" placeholder="192.168.88.1" required></label>
  <div class="dlg-row" style="gap:12px">
    <label style="flex:1">Community SNMP <small id="eqcomm-help">Somente leitura (v2c).</small><input id="eqcomm" type="password" maxlength="64" autocomplete="new-password" placeholder="public"></label>
    <label style="width:110px">Porta <small>&nbsp;</small><input id="eqport" inputmode="numeric" maxlength="5" placeholder="161"></label>
  </div>
  <label>Interfaces monitoradas <small>Separe por vírgula, com os nomes do equipamento (ex.: ether1, ether2 no MikroTik; Gi0/1 em switches).</small><input id="eqifs" maxlength="400" autocomplete="off" placeholder="ether1, ether2, ether5" required></label>
  <p class="form-error" id="eqerr" role="alert"></p>
  <div class="dlg-actions"><button type="button" class="btn" id="eqcancel">Cancelar</button><button class="btn p" id="eqsave">Salvar e testar</button></div>
</form></dialog>

<div id="msg" hidden role="status"></div>

<script>
'use strict';
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const store={get(k,d){try{const v=localStorage.getItem(k);return v===null?d:v}catch(e){return d}},set(k,v){try{localStorage.setItem(k,v)}catch(e){}}};

/* ------------------------------------------------------------ ícones */
const IC={
  plus:'<path d="M12 5v14M5 12h14"/>', search:'<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
  refresh:'<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>', edit:'<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
  trash:'<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M6 6l1 14h10l1-14"/>', rows:'<path d="M4 6h16M4 12h16M4 18h16"/>',
  sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon:'<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/>',
  bell:'<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>',
  logout:'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>'};
const ic=(n,s=16)=>`<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${IC[n]}</svg>`;

/* ----------------------------------------------------------- formatos */
function dur(sec){sec=Math.max(0,Math.round(sec)); if(sec<60) return sec+' s'; let m=Math.floor(sec/60); if(m<60) return m+' min';
  const h=Math.floor(m/60); m%=60; if(h<24) return m?`${h} h ${m} min`:`${h} h`; const d=Math.floor(h/24), hh=h%24; return hh?`${d} d ${hh} h`:`${d} d`}
const fmt=t=>new Date(t*1000).toLocaleString('pt-BR',{dateStyle:'short',timeStyle:'medium'});
let toastTimer;
function toast(msg,err){const m=$('#msg'); m.textContent=msg; m.className=err?'err':''; m.hidden=false; clearTimeout(toastTimer); toastTimer=setTimeout(()=>m.hidden=true,3800)}
async function api(path,method='GET',body){
  const r=await fetch(path,{method,headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
  if(r.status===401&&path!=='/api/logout'){location.reload(); throw new Error('Sessão expirada. Entre novamente.')}   // volta para a tela do código
  const j=await r.json().catch(()=>({})); if(!r.ok) throw new Error(j.error||'Erro '+r.status); return j}

/* --------------------------------------------- atualização eficiente do DOM
   A lista é atualizada por diferença: só o que mudou é tocado. Assim 200+ linhas
   atualizam a cada poucos segundos sem piscar, sem perder foco e sem fechar menus. */
function parse(html){const t=document.createElement('template'); t.innerHTML=html.trim(); return t.content.firstElementChild}
function syncAttrs(a,b){
  for(const at of [...a.attributes]) if(at.name!=='data-k'&&!b.hasAttribute(at.name)) a.removeAttribute(at.name);
  for(const at of b.attributes) if(a.getAttribute(at.name)!==at.value) a.setAttribute(at.name,at.value)}
function morph(a,b,depth){
  syncAttrs(a,b);
  if(depth===0){ if(a.innerHTML!==b.innerHTML) a.innerHTML=b.innerHTML; return }
  const ca=[...a.children], cb=[...b.children];
  if(ca.length!==cb.length||ca.some((c,i)=>c.tagName!==cb[i].tagName)){ a.replaceChildren(...cb); return }
  ca.forEach((c,i)=>morph(c,cb[i],depth-1))}
function patchList(container,items,keyOf,htmlOf,depth){
  const old=new Map(); for(const el of container.children) old.set(el.dataset.k,el);
  const used=new Set(); let i=0;
  for(const it of items){
    const k=String(keyOf(it)), html=htmlOf(it); let el=old.get(k);
    if(!el){ el=parse(html); el.dataset.k=k; el._html=html }
    else if(el._html!==html){ morph(el,parse(html),depth); el._html=html }
    used.add(k);
    const cur=container.children[i]; if(cur!==el) container.insertBefore(el,cur||null);
    i++}
  for(const [k,el] of old) if(!used.has(k)) el.remove()}

/* ---------------------------------------------------------------- estado */
let S=null, timer=null;
const app={tab:'devices',q:'',st:'',cat:'',sort:{k:store.get('nw_sk','status'),d:Number(store.get('nw_sd','1'))||1},
  compact:store.get('nw_density','')==='compact',sel:new Set(),open:new Set(),last:null,editing:null,eqEditing:null};
let scanSel=new Set(), rowCat={}, lastScan='', catSig='';

const isDeg=d=>d.status==='online'&&d.fails>0;
const stOf=d=>d.status==='offline'?'down':isDeg(d)?'wait':d.status==='online'?'up':'unk';
const RANK={down:0,wait:1,unk:2,up:3};
const stLabel=d=>({down:'Offline',wait:`Sem resposta ${d.fails}/${S.fails_to_offline}`,unk:'Aguardando',up:'Online'}[stOf(d)]);
const collator=new Intl.Collator('pt-BR',{numeric:true,sensitivity:'base'});
const ipn=h=>{const m=/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h); return m?((+m[1]*256+ +m[2])*256+ +m[3])*256+ +m[4]:null};
const cmpHost=(a,b)=>{const x=ipn(a.host),y=ipn(b.host); if(x!==null&&y!==null) return x-y; if(x!==null) return -1; if(y!==null) return 1; return collator.compare(a.host,b.host)};
const SORTS={
  status:(a,b)=>RANK[stOf(a)]-RANK[stOf(b)]||collator.compare(a.name,b.name),
  name:(a,b)=>collator.compare(a.name,b.name), host:cmpHost,
  category:(a,b)=>collator.compare(a.category,b.category)||collator.compare(a.name,b.name),
  latency:(a,b)=>(a.latency??1e9)-(b.latency??1e9), uptime:(a,b)=>a.uptime-b.uptime, since:(a,b)=>(a.since??0)-(b.since??0)};

function visibleDevices(){
  const q=app.q.trim().toLowerCase(), f=SORTS[app.sort.k]||SORTS.status;
  return S.devices.filter(d=>(!app.st||d.status===app.st)&&(!app.cat||d.category===app.cat)&&
      (!q||`${d.name} ${d.host} ${d.category} ${d.mac} ${d.vendor}`.toLowerCase().includes(q)))
    .sort((a,b)=>app.sort.d*f(a,b)||a.id-b.id)}

/* -------------------------------------------------------- dispositivos */
function trackHTML(d){
  const span=S.window_to-S.window_from, p=t=>(t-S.window_from)/span*100;
  let h=`<div class="track" role="img" aria-label="Disponibilidade nas últimas 24 horas: ${d.uptime.toFixed(2)}%">`;
  const pre=p(d.monitored_since); if(pre>0.2) h+=`<span class="pre" style="width:${pre.toFixed(1)}%" title="Antes do cadastro"></span>`;
  for(const [s,e] of d.outages_24h){const w=Math.max(p(e)-p(s),.5);
    h+=`<span class="tseg" style="left:${p(s).toFixed(1)}%;width:${w.toFixed(1)}%" title="Offline de ${esc(fmt(s))} até ${esc(fmt(e))}"></span>`}
  return h+'</div>'}
function sinceText(d){
  if(isDeg(d)) return 'Sem resposta há '+dur(S.now-d.first_fail);
  if(!d.since||d.status==='unknown') return '–';
  return (d.status==='online'?'No ar há ':'Fora há ')+dur(S.now-d.since)}
function detailHTML(d){
  const kv=(k,v)=>`<div><dt>${k}</dt><dd>${v}</dd></div>`;
  return `<div class="detail"><dl>`+kv('Último ping',d.detail?esc(d.detail):'–')+kv('Última verificação',d.last_check?esc(fmt(d.last_check)):'–')+
    kv('MAC conhecido',d.mac?esc(d.mac)+(d.vendor?' ('+esc(d.vendor)+')':''):'–')+kv('Cadastrado em',esc(fmt(d.created)))+
    kv('No estado atual desde',d.since?esc(fmt(d.since)):'–')+`</dl></div>`}
function rowHTML(d){
  const st=stOf(d), sel=app.sel.has(d.id), open=app.open.has(d.id), n=esc(d.name);
  const lat=d.latency==null?'–':d.latency.toFixed(d.latency<10?1:0)+' ms';
  return `<div class="item"><div class="row st-${st}${sel?' selected':''}">
    <div class="k-chk"><input type="checkbox" data-sel="${d.id}" ${sel?'checked':''} aria-label="Selecionar ${n}"></div>
    <div class="k-status"><span class="pill ${st}"><i></i>${esc(stLabel(d))}</span></div>
    <div class="k-name"><button class="namebtn" data-act="expand" aria-expanded="${open}" title="Ver detalhes"><span class="nm">${n}</span><span class="host">${esc(d.host)}</span>${(st==='down'||st==='wait')&&d.detail?`<span class="why" title="${esc(d.detail)}">${esc(d.detail)}</span>`:''}</button></div>
    <div class="k-cat"><span class="chip">${esc(d.category)}</span></div>
    <div class="k-lat">${lat}</div>
    <div class="k-bar">${trackHTML(d)}<span class="pct">${(Math.floor(d.uptime*10)/10).toFixed(1)}%</span></div>
    <div class="k-since">${esc(sinceText(d))}</div>
    <div class="k-act"><button class="ib" data-act="check" title="Verificar agora" aria-label="Verificar ${n}">${ic('refresh',15)}</button>
      <button class="ib" data-act="edit" title="Editar" aria-label="Editar ${n}">${ic('edit',15)}</button>
      <button class="ib danger" data-act="del" title="Excluir" aria-label="Excluir ${n}">${ic('trash',15)}</button></div>
  </div>${open?detailHTML(d):''}</div>`}
const cellHTML=(d,dim)=>`<button class="cell ${stOf(d)}${dim?' dim':''}" data-id="${d.id}" title="${esc(d.name)} (${esc(d.host)}): ${esc(stLabel(d))}" aria-label="${esc(d.name)}: ${esc(stLabel(d))}"></button>`;

function fillCatSelects(){
  const cats=[...new Set([...S.categories,...S.devices.map(d=>d.category)])], sig=cats.join('|');
  if(sig===catSig) return; catSig=sig;
  for(const id of ['#devcat','#selcat','#bulkcat']){const el=$(id), v=el.value;
    el.innerHTML=cats.map(c=>`<option>${esc(c)}</option>`).join(''); el.value=cats.includes(v)?v:S.default_category}}

function renderDevices(){
  const ids=new Set(S.devices.map(d=>d.id));
  for(const id of [...app.sel]) if(!ids.has(id)) app.sel.delete(id);
  for(const id of [...app.open]) if(!ids.has(id)) app.open.delete(id);
  const cats=[...new Set([...S.categories,...S.devices.map(d=>d.category)])];
  if(app.cat&&!cats.includes(app.cat)) app.cat='';
  fillCatSelects();
  const has=S.devices.length>0; $('#devEmpty').hidden=has; $('#devMain').hidden=!has; if(!has) return;

  const list=visibleDevices(), shown=new Set(list.map(d=>d.id)), filtered=!!(app.q||app.st||app.cat), c=S.counts;
  // mapa da rede (ordem por IP, estável)
  patchList($('#fleet'),S.devices.slice().sort(cmpHost),d=>d.id,d=>cellHTML(d,filtered&&!shown.has(d.id)),0);
  const avg=S.devices.reduce((s,d)=>s+d.uptime,0)/S.devices.length;
  $('#fleetinfo').textContent=`${S.devices.length} dispositivos, disponibilidade média nas últimas 24 h: ${(Math.floor(avg*10)/10).toLocaleString('pt-BR',{minimumFractionDigits:1})}%`;
  // filtros
  $('#seg').innerHTML=[['','Todos',S.devices.length],['offline','Offline',c.offline],['online','Online',c.online],['unknown','Aguardando',c.unknown]]
    .map(([k,l,n])=>`<button type="button" data-st="${k}" class="${app.st===k?'on':''}" aria-pressed="${app.st===k}">${l}<span>${n}</span></button>`).join('');
  const per=n=>{const l=S.devices.filter(d=>d.category===n); return {n:l.length,off:l.filter(d=>d.status==='offline').length}};
  const bad=n=>n?`<span class="bad" title="offline">${n}</span>`:'';
  $('#cats').innerHTML=`<button type="button" data-cat="" class="${app.cat?'':'on'}">Todas<span class="n">${S.devices.length}</span></button>`+
    cats.filter(n=>per(n).n||n===app.cat).map(n=>`<button type="button" data-cat="${esc(n)}" class="${n===app.cat?'on':''}">${esc(n)}<span class="n">${per(n).n}</span>${bad(per(n).off)}</button>`).join('');
  $('#count').textContent=`Mostrando ${list.length} de ${S.devices.length}`;
  $$('.sortbtn').forEach(b=>{const on=b.dataset.sort===app.sort.k; b.classList.toggle('on',on); b.setAttribute('aria-pressed',on); b.querySelector('.arr').textContent=on?(app.sort.d>0?'▲':'▼'):''});
  $('#density').classList.toggle('on',app.compact); $('#densitylbl').textContent=app.compact?'Confortável':'Compacto'; $('#list').classList.toggle('compact',app.compact);
  // lista
  patchList($('#list'),list,d=>d.id,rowHTML,2);
  $('#listEmpty').hidden=list.length>0; $('#list').hidden=!list.length;
  const nsel=list.filter(d=>app.sel.has(d.id)).length, all=$('#selall');
  all.checked=list.length>0&&nsel===list.length; all.indeterminate=nsel>0&&nsel<list.length;
  $('#bulk').hidden=!app.sel.size; $('#bulkn').textContent=`${app.sel.size} ${app.sel.size===1?'selecionado':'selecionados'}`}

function focusDevice(id){
  if(!visibleDevices().some(d=>d.id===id)){app.q='';app.st='';app.cat='';$('#q').value=''}
  renderDevices();
  const el=$('#list').querySelector(`.item[data-k="${id}"]`); if(!el) return;
  el.scrollIntoView({block:'center',behavior:'smooth'});
  const r=el.firstElementChild; r.classList.add('flash'); setTimeout(()=>r.classList.remove('flash'),1800)}

/* ---------------------------------------------------------- cabeçalho */
function renderHeader(){
  const c=S.counts;
  $('#stats').innerHTML=`<button class="stat" data-st="online" type="button"><i class="d up"></i><b>${c.online}</b>online</button>`+
    `<button class="stat" data-st="offline" type="button"><i class="d down"></i><b>${c.offline}</b>offline</button>`+
    (c.unknown?`<button class="stat" data-st="unknown" type="button"><i class="d"></i><b>${c.unknown}</b>aguardando</button>`:'');
  const set=(id,text,cls)=>{const e=$(id); e.hidden=!text; e.textContent=text||''; e.className='cnt'+(cls?' '+cls:'')};
  const fresh=S.scan.found.filter(x=>!x.registered).length;
  set('#c-devices',S.devices.length||'');
  set('#c-scan',S.scan.running?'varrendo':(fresh?fresh+(fresh===1?' novo':' novos'):''),S.scan.running?'wait':'');
  set('#c-outages',c.offline?c.offline+' em andamento':'','bad')
  const ds=S.snmp.devices, downs=ds.reduce((n,d)=>n+(d.ok?d.ports.filter(p=>p.state==='down').length:0),0), noSnmp=ds.filter(d=>!d.ok&&d.last_poll).length;
  set('#c-snmp',downs?downs+(downs===1?' porta down':' portas down'):(noSnmp?noSnmp+' sem SNMP':''),downs?'bad':'wait')}

/* --------------------------------------------------- histórico de quedas */
function renderOutages(){
  const q=$('#oq').value.trim().toLowerCase(), only=$('#oopen').checked;
  const rows=S.outages.filter(o=>(!only||!o.ended)&&(!q||`${o.name} ${o.host} ${o.category}`.toLowerCase().includes(q)));
  $('#ocount').textContent=`${rows.length} ${rows.length===1?'registro':'registros'}`+(S.outages.length>=300?' (as 300 mais recentes)':'');
  $('#outages').innerHTML=rows.length?`<table><thead><tr><th>Dispositivo</th><th>Categoria</th><th>Ficou offline em (e motivo)</th><th>Voltou em (e resposta recebida)</th><th>Duração</th></tr></thead><tbody>`+
    rows.map(o=>`<tr><td><b>${esc(o.name)}</b><span class="host">${esc(o.host)}</span></td><td><span class="chip">${esc(o.category)}</span></td><td>${esc(fmt(o.started))}${o.start_reason?`<span class="detail-l" title="O que o ping mostrou ao cair">${esc(o.start_reason)}</span>`:''}</td>
      <td>${o.ended?esc(fmt(o.ended)):'<span class="tag down">Ainda offline</span>'}${o.end_reason?`<span class="detail-l" title="Resposta que confirmou o retorno">${esc(o.end_reason)}</span>`:''}</td><td>${dur(o.duration)}${o.ended?'':' e contando'}</td></tr>`).join('')+'</tbody></table>'
    :'<div class="empty"><strong>Nenhuma queda encontrada</strong>Quando um dispositivo parar de responder, o início e o retorno aparecem aqui.</div>'}

/* ----------------------------------------------------------- varredura */
const PHASE={ping:'Testando ping',arp:'Consultando a tabela ARP',nmap:'nmap verificando portas',names:'Resolvendo nomes'};
function renderScan(){
  const s=S.scan, key=JSON.stringify([s,[...scanSel],rowCat,S.categories]);
  const inp=$('#network'); if(!inp.value&&document.activeElement!==inp) inp.value=store.get('nw_network','')||S.default_network;
  $('#scanbtn').disabled=s.running; $('#scanbtn').textContent=s.running?'Varrendo…':(s.finished?'Varrer novamente':'Iniciar varredura');
  $('#deeplbl').hidden=!s.nmap; $('#deep').disabled=s.running;
  $('#scanhint').innerHTML='Um /24 tem 254 endereços e leva alguns segundos; dá para digitar várias redes separadas por vírgula. '+(s.nmap
    ?`nmap encontrado: a varredura também mostra MAC, fabricante e portas abertas (${esc(s.ports.join(', '))}).`
    :'nmap não encontrado: só ping e tabela ARP, sem portas. Para ativar: <code>sudo apt install nmap</code> (não precisa reiniciar).');
  if(key===lastScan) return; lastScan=key;
  let h='';
  if(s.running){
    const st=(PHASE[s.phase]||'Varrendo')+' em '+esc(s.networks.join(', '));
    h+=`<div class="empty"><progress ${s.total?`max="${s.total}" value="${s.done}"`:''}></progress>${st}${s.total?`: ${s.done} de ${s.total}.`:'…'} ${s.found.length} ${s.found.length===1?'encontrado':'encontrados'} até agora.</div>`}
  if(s.warning) h+=`<div class="note">Aviso: ${esc(s.warning)}</div>`;
  if(s.error) h+=`<div class="empty txt-down">Falha: ${esc(s.error)}</div>`;
  else if(!s.running&&!s.finished) h+='<div class="empty"><strong>Nenhuma varredura executada</strong>Clique em “Iniciar varredura” para listar os equipamentos da rede.</div>';
  else if(!s.running&&!s.found.length) h+=`<div class="empty"><strong>Nenhum host encontrado</strong>em ${esc(s.networks.join(', '))}. O servidor precisa alcançar essa rede.</div>`;
  if(s.found.length){
    const fresh=s.found.filter(x=>!x.registered), P=s.nmap, def=$('#bulkcat').value||S.default_category;
    const cats=[...new Set([...S.categories,...S.devices.map(d=>d.category)])];
    const eff=x=>rowCat[x.ip]||x.suggested||def;
    const opts=cur=>cats.map(c=>`<option${c===cur?' selected':''}>${esc(c)}</option>`).join('');
    const web={80:'http',8080:'http',81:'http',8000:'http',443:'https',8443:'https'};
    const ptag=(x,p)=>{const nm=s.port_names[p], lbl=esc(p+(nm?' '+nm:'')), sch=web[p];
      return sch?`<a class="ptag" href="${sch}://${esc(x.ip)}${p===80||p===443?'':':'+p}" target="_blank" rel="noopener noreferrer" title="Abrir no navegador">${lbl}</a>`:`<span class="ptag">${lbl}</span>`};
    const ports=x=>{if(!Object.keys(x.ports||{}).length) return '–'; const o=s.ports.filter(p=>x.ports[p]==='open'); return o.length?o.map(p=>ptag(x,p)).join(''):'<span class="mute">nenhuma</span>'};
    h+=`<div class="scan-actions" style="display:flex;gap:10px;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line)"><span class="mute grow">${s.found.length} ${s.found.length===1?'host encontrado':'hosts encontrados'}, ${fresh.length} ainda sem cadastro.</span>
      <button class="btn p" data-a="addsel" ${scanSel.size?'':'disabled'}>Adicionar selecionados (${scanSel.size})</button>
      <button class="btn" data-a="addall" ${fresh.length?'':'disabled'}>Adicionar todos os novos (${fresh.length})</button></div>`+
    `<table><thead><tr><th><input type="checkbox" data-a="scanall" aria-label="Selecionar todos os novos" ${fresh.length&&fresh.every(x=>scanSel.has(x.ip))?'checked':''} ${fresh.length?'':'disabled'}></th><th>IP</th><th>Nome encontrado</th><th>MAC e fabricante</th>${P?'<th>Portas abertas</th>':''}<th>Latência</th><th>Categoria</th><th>Situação</th></tr></thead><tbody>`+
    s.found.map(x=>`<tr><td>${x.registered?'':`<input type="checkbox" data-ip="${esc(x.ip)}" ${scanSel.has(x.ip)?'checked':''} aria-label="Selecionar ${esc(x.ip)}">`}</td>
      <td><span class="host" style="color:var(--ink);font-size:13px">${esc(x.ip)}</span></td><td>${esc(x.hostname)||'<i class="mute">sem nome</i>'}</td>
      <td>${x.mac?`<span class="host" style="color:var(--ink)">${esc(x.mac)}</span><span class="detail-l">${esc(x.vendor||'fabricante desconhecido')}</span>`:'–'}</td>
      ${P?`<td>${ports(x)}</td>`:''}
      <td>${x.latency==null?'–':x.latency.toFixed(x.latency<10?1:0)+' ms'}</td>
      <td>${x.registered?'–':`<select class="rowcat" data-ip="${esc(x.ip)}" aria-label="Categoria de ${esc(x.ip)}">${opts(eff(x))}</select>${!rowCat[x.ip]&&x.suggested?'<span class="detail-l">sugerida pelo fabricante</span>':''}`}</td>
      <td>${x.registered?'<span class="tag up">Já monitorado</span>':'<span class="tag">Novo</span>'}</td></tr>`).join('')+'</tbody></table>'}
  $('#scan').innerHTML=h}

/* -------------------------------------------------- categorias (diálogo) */
function renderCatList(){
  const cnt=c=>S.devices.filter(d=>d.category===c).length;
  $('#catlist').innerHTML='<table><thead><tr><th>Categoria</th><th>Dispositivos</th><th></th></tr></thead><tbody>'+S.categories.map(c=>{
    const dflt=c===S.default_category;
    return `<tr><td><b>${esc(c)}</b></td><td>${cnt(c)}</td><td style="text-align:right;white-space:nowrap">`+(dflt
      ?'<span class="tag" title="Recebe os dispositivos de categorias excluídas">padrão</span>'
      :`<button class="link" data-a="catren" data-c="${esc(c)}" type="button">Renomear</button> &nbsp; <button class="link d" data-a="catdel" data-c="${esc(c)}" type="button">Excluir</button>`)+'</td></tr>'}).join('')+'</tbody></table>'}

/* ------------------------------------------------ Portas SNMP (equipamentos) */
const fmtRate=b=>{if(b==null) return '–'; const u=['bps','kbps','Mbps','Gbps']; let i=0,v=b; while(v>=1000&&i<3){v/=1000;i++}
  return (i===0?Math.round(v):v>=100?Math.round(v):v>=10?v.toFixed(1):v.toFixed(2)).toString().replace('.',',')+' '+u[i]};
const fmtSpeed=m=>!m?'–':m>=1000?(m/1000)+' Gbps':m+' Mbps';
const fmtInt=n=>n==null?'–':Number(n).toLocaleString('pt-BR');
const MT_STATE={up:['UP','up'],down:['DOWN','down'],disabled:['Desabilitada','unk'],missing:['Não encontrada','unk'],unknown:['Aguardando leitura','unk']};
function spark(sm){
  if(sm.length<2) return '<div class="spark" style="display:grid;place-items:center;color:var(--faint);font-size:12px">coletando amostras…</div>';
  const W=300,H=54,P=3, max=Math.max(1,...sm.map(s=>Math.max(s[1],s[2])));
  const x=i=>P+i*(W-2*P)/(sm.length-1), y=v=>H-P-(v/max)*(H-2*P), line=k=>sm.map((s,i)=>x(i).toFixed(1)+','+y(s[k]).toFixed(1)).join(' ');
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Tráfego dos últimos minutos"><polyline class="ln-in" points="${line(1)}"/><polyline class="ln-out" points="${line(2)}"/></svg>
    <div class="spark-note"><div><span class="lg-in">entrada</span><span class="lg-out">saída</span></div><span>últimos ${dur(sm[sm.length-1][0]-sm[0][0])}, pico ${fmtRate(max)}</span></div>`}
function portCard(p,ok){
  const [lbl,cls]=MT_STATE[p.state]||MT_STATE.unknown;
  let body;
  if(p.found===false) body=`<p class="mute" style="margin:10px 0 0">Esta interface não existe no roteador. Confira o nome com <code>/interface print</code>.</p>`;
  else if(p.state==='unknown') body='<p class="mute" style="margin:10px 0 0">Aguardando a primeira leitura…</p>';
  else{
    const live=p.state==='up', bar=(v,c)=>`<div class="ubar"><i style="width:${live&&v?v:0}%;background:var(${c})"></i></div>`;
    body=`<div class="pmeta"><span>Velocidade <b>${fmtSpeed(p.speed)}</b></span>${p.since?`<span>No estado há <b>${dur(S.now-p.since)}</b></span>`:''}</div>
      <div class="rates"><div class="rate"><small>Entrada (download)</small><b>${live?fmtRate(p.in_bps):'–'}</b>${bar(p.in_pct,'--in')}<small>${live&&p.in_pct!=null?p.in_pct+'% do link':'&nbsp;'}</small></div>
      <div class="rate"><small>Saída (upload)</small><b>${live?fmtRate(p.out_bps):'–'}</b>${bar(p.out_pct,'--out')}<small>${live&&p.out_pct!=null?p.out_pct+'% do link':'&nbsp;'}</small></div></div>
      ${spark(p.samples)}
      <div class="perr"><span>Erros de entrada <b class="${p.in_errors?'bad':''}">${fmtInt(p.in_errors)}</b></span><span>Erros de saída <b class="${p.out_errors?'bad':''}">${fmtInt(p.out_errors)}</b></span></div>`}
  const alias=p.found===false||p.alias==null?'':(p.alias?`<div class="palias" title="Descrição da porta: ${esc(p.alias)}">${esc(p.alias)}</div>`:'<div class="palias none">sem descrição</div>');
  return `<div class="pcard ${esc(p.state)}${ok?'':' stale'}"><div class="phead"><h3>${esc(p.name)}</h3><span class="pill ${cls}"><i></i>${lbl}</span></div>${alias}${body}</div>`}
function eqBlock(d){
  const label=d.name||d.sysname||d.host;
  const info=`<div class="sheet eq-info"><span class="pill ${d.ok?'up':'down'}"><i></i>${d.ok?'SNMP respondendo':'Sem resposta SNMP'}</span>
    <div class="kv"><small>Equipamento</small><b>${esc(label)}</b> <span class="host">${esc(d.host)}:${d.port}</span></div>
    ${d.descr?`<div class="kv" style="min-width:0;max-width:250px"><small>Modelo</small><span class="nm" style="display:block" title="${esc(d.descr)}">${esc(d.descr)}</span></div>`:''}
    ${d.uptime!=null?`<div class="kv"><small>Ligado há</small><b>${dur(d.uptime)}</b></div>`:''}
    ${d.last_poll?`<div class="kv"><small>Última leitura</small><b>${new Date(d.last_poll*1000).toLocaleTimeString('pt-BR')}</b></div>`:''}
    <span class="grow"></span><button class="btn" data-eq="poll" data-id="${d.id}" type="button">Atualizar agora</button>
    <button class="btn" data-eq="edit" data-id="${d.id}" type="button">Editar</button><button class="btn danger" data-eq="del" data-id="${d.id}" type="button">Excluir</button></div>`;
  const warn=!d.ok&&d.error?`<div class="sheet note" style="margin-bottom:14px;color:var(--down)">${esc(d.error)}</div>`:'';
  return `<section class="eq">${info}${warn}<div class="eq-grid">${d.ports.map(p=>portCard(p,d.ok)).join('')}</div></section>`}
function renderSnmp(){
  const m=S.snmp, box=$('#eqbody'), ds=m.devices;
  $('#eqcount').textContent=ds.length?`${ds.length} ${ds.length===1?'equipamento':'equipamentos'}`:'';
  if(!ds.length){
    box.innerHTML=`<div class="sheet empty"><strong>Monitoramento de portas por SNMP</strong>
      Acompanhe o link, a velocidade, o tráfego e os erros das portas de roteadores e switches, com histórico de quedas. Dá para cadastrar vários equipamentos.<br>
      <button class="btn p" data-eq="add" type="button">Adicionar equipamento</button><br>
      <span class="mute" style="display:inline-block;margin-top:18px;font-size:13px">Habilite o SNMP v2c (somente leitura) no equipamento. Exemplo no MikroTik (Winbox &gt; New Terminal):</span><br>
      <code class="cmd">/snmp set enabled=yes
/snmp community set [ find default=yes ] name=public addresses=IP_DO_NETWATCH/32</code></div>`; return}
  const names=Object.fromEntries(ds.map(d=>[d.id,d.name||d.sysname||d.host])), evs=m.events.slice(0,100);
  const aliases={}; ds.forEach(d=>d.ports.forEach(p=>{if(p.alias) aliases[d.id+'|'+p.name]=p.alias}));
  const ev=evs.length?`<table><thead><tr><th>Equipamento</th><th>Porta</th><th>Caiu em</th><th>Voltou em</th><th>Duração</th><th>Observação</th></tr></thead><tbody>`+
    evs.map(e=>`<tr><td><b>${esc(names[e.device_id]||'–')}</b></td><td><span class="host" style="color:var(--ink);font-size:13px;display:inline">${esc(e.iface)}</span>${aliases[e.device_id+'|'+e.iface]?`<span class="palias" title="${esc(aliases[e.device_id+'|'+e.iface])}">${esc(aliases[e.device_id+'|'+e.iface])}</span>`:''}</td><td>${esc(fmt(e.started))}</td>
      <td>${e.ongoing?'<span class="tag down">Ainda down</span>':esc(fmt(e.ended))}</td><td>${dur(e.duration)}${e.ongoing?' e contando':''}</td><td class="mute">${esc(e.reason)}</td></tr>`).join('')+'</tbody></table>'
    :'<div class="empty"><strong>Nenhuma queda de porta registrada</strong>Quando um link cair e voltar, o horário (do próprio equipamento) aparece aqui.</div>';
  box.innerHTML=ds.map(eqBlock).join('')+`<h2 class="eq-h">Histórico das portas</h2><div class="sheet">${ev}</div>`}
$('#p-snmp').addEventListener('click',async e=>{const b=e.target.closest('[data-eq]'); if(!b) return;
  const act=b.dataset.eq, id=Number(b.dataset.id), d=S.snmp.devices.find(x=>x.id===id);
  if(act==='add') return openEq(null);
  if(!d) return;
  try{
    if(act==='edit') openEq(d);
    if(act==='poll'){b.disabled=true; const r=await api(`/api/snmp/devices/${id}/poll`,'POST',{}); r.ok?toast('Leitura atualizada'):toast(r.error,true); load()}
    if(act==='del'&&confirm(`Excluir “${d.name||d.sysname||d.host}” e o histórico de quedas das portas dele?`)){await api('/api/snmp/devices/'+id,'DELETE'); toast('Equipamento excluído'); load()}
  }catch(x){toast(x.message,true)}});
function openEq(d){
  app.eqEditing=d?d.id:null; $('#eqdlg-t').textContent=d?'Editar equipamento SNMP':'Adicionar equipamento SNMP';
  $('#eqname').value=d?d.name:''; $('#eqhost').value=d?d.host:''; $('#eqcomm').value=''; $('#eqcomm').placeholder=d?'•••••• (mantida; digite para trocar)':'public';
  $('#eqport').value=d?d.port:161; $('#eqifs').value=d?d.interfaces.join(', '):''; $('#eqerr').textContent='';
  $('#eqdlg').showModal(); $('#eqhost').focus()}
$('#eqform').addEventListener('submit',async e=>{e.preventDefault(); const err=$('#eqerr'); err.textContent=''; $('#eqsave').disabled=true; $('#eqsave').textContent='Testando…';
  const body={name:$('#eqname').value,host:$('#eqhost').value,community:$('#eqcomm').value,port:$('#eqport').value,interfaces:$('#eqifs').value};
  try{
    const r=app.eqEditing?await api('/api/snmp/devices/'+app.eqEditing,'PATCH',body):await api('/api/snmp/devices','POST',body);
    if(!r.ok){app.eqEditing=r.id; $('#eqdlg-t').textContent='Editar equipamento SNMP'; err.textContent='Salvo, mas o equipamento não respondeu: '+r.error; load(); return}   // próximo envio edita o mesmo
    $('#eqdlg').close(); toast('Equipamento conectado'); load()}
  catch(x){err.textContent=x.message}
  finally{$('#eqsave').disabled=false; $('#eqsave').textContent='Salvar e testar'}});
$('#eqcancel').addEventListener('click',()=>$('#eqdlg').close());

/* ------------------------------------------------------------- Telegram */
function renderTg(){
  const t=S.telegram, b=$('#tgbtn'); b.classList.toggle('dot-on',t.enabled&&!t.last_error); b.classList.toggle('dot-err',t.enabled&&!!t.last_error);
  b.title=!t.enabled?'Notificações no Telegram (desativadas)':t.last_error?'Telegram com falha: '+t.last_error:'Notificações no Telegram (ativas)'}
function openTg(){
  const t=S.telegram; $('#tgon').checked=t.enabled; $('#tgtoken').value=''; $('#tgtoken').placeholder=t.has_token?'•••••• (mantido; digite para trocar)':'123456789:AAE…';
  $('#tgchat').value=t.chat_id; $('#tgdown').checked=t.on_down; $('#tgup').checked=t.on_up; $('#tgports').checked=t.on_ports; $('#tgchats').innerHTML=''; $('#tgerr').textContent='';
  $('#tgstatus').textContent=t.last_error?'Última falha: '+t.last_error:(t.last_ok?'Última mensagem enviada às '+new Date(t.last_ok*1000).toLocaleTimeString('pt-BR')+' ('+t.sent+' enviadas).':'');
  $('#tgdlg').showModal(); (t.has_token?$('#tgchat'):$('#tgtoken')).focus()}
$('#tgbtn').addEventListener('click',()=>S&&openTg());
$('#tgcancel').addEventListener('click',()=>$('#tgdlg').close());
$('#tgfind').addEventListener('click',async()=>{const box=$('#tgchats'), err=$('#tgerr'); err.textContent=''; box.innerHTML='';
  $('#tgfind').disabled=true; $('#tgfind').textContent='Buscando…';
  try{const r=await api('/api/telegram/chats','POST',{token:$('#tgtoken').value});
    box.innerHTML=r.chats.map(c=>`<button type="button" data-chat="${esc(c.id)}">${esc(c.name)}<small>${esc(c.type)} ${esc(c.id)}</small></button>`).join('')}
  catch(x){err.textContent=x.message}
  finally{$('#tgfind').disabled=false; $('#tgfind').textContent='Descobrir'}});
$('#tgchats').addEventListener('click',e=>{const b=e.target.closest('[data-chat]'); if(b){$('#tgchat').value=b.dataset.chat; $('#tgchats').innerHTML=''}});
$('#tgform').addEventListener('submit',async e=>{e.preventDefault(); const err=$('#tgerr'); err.textContent=''; $('#tgsave').disabled=true; $('#tgsave').textContent=$('#tgon').checked?'Enviando teste…':'Salvando…';
  try{const r=await api('/api/telegram/config','POST',{enabled:$('#tgon').checked,token:$('#tgtoken').value,chat_id:$('#tgchat').value,on_down:$('#tgdown').checked,on_up:$('#tgup').checked,on_ports:$('#tgports').checked});
    if(!r.ok){err.textContent='Configuração salva, mas o envio falhou: '+r.error; load(); return}
    $('#tgdlg').close(); toast($('#tgon').checked?'Telegram conectado: mensagem de teste enviada':'Notificações desativadas'); load()}
  catch(x){err.textContent=x.message}
  finally{$('#tgsave').disabled=false; $('#tgsave').textContent='Salvar e testar'}});

/* -------------------------------------------------------------- render */
function render(){
  renderHeader(); renderTg(); renderDevices(); if(app.tab==='outages') renderOutages(); if(app.tab==='snmp') renderSnmp();
  if($('#catdlg').open) renderCatList(); renderScan()}

function setTab(name){
  if(name==='mikrotik') name='snmp';   // favoritos antigos
  if(!['devices','scan','outages','snmp'].includes(name)) name='devices';
  app.tab=name;
  for(const b of $$('.tabs [data-tab]')){const on=b.dataset.tab===name; b.setAttribute('aria-selected',on); b.tabIndex=on?0:-1}
  for(const n of ['devices','scan','outages','snmp']) $('#p-'+n).hidden=n!==name;
  store.set('nw_tab',name); history.replaceState(null,'','#'+name);
  if(S){ if(name==='outages') renderOutages(); if(name==='scan'){lastScan='';renderScan()} if(name==='snmp') renderSnmp() }}

async function load(){
  clearTimeout(timer);
  if(document.hidden){timer=setTimeout(load,5000); return}
  try{S=await api('/api/state'); $('#live').textContent='Atualizado às '+new Date().toLocaleTimeString('pt-BR'); $('#live').className='live'}
  catch(e){$('#live').textContent='Sem conexão com o servidor'; $('#live').className='live bad'; timer=setTimeout(load,5000); return}
  try{render()}catch(e){console.error(e)}
  timer=setTimeout(load,S.scan.running?1000:5000)}
document.addEventListener('visibilitychange',()=>{if(!document.hidden) load()});

/* ------------------------------------------------ diálogo de dispositivo */
function openDev(dev){
  app.editing=dev?dev.id:null;
  $('#devdlg-t').textContent=dev?'Editar dispositivo':'Adicionar dispositivo';
  $('#devsave').textContent=dev?'Salvar alterações':'Adicionar'; $('#devmore').hidden=!!dev;
  $('#devname').value=dev?dev.name:''; $('#devhost').value=dev?dev.host:''; $('#devhost').readOnly=!!dev;
  $('#devhost-help').textContent=dev?'Não pode ser alterado. Para trocar, exclua e cadastre de novo.':'IPv4 ou nome completo (FQDN).';
  $('#devcat').value=dev?dev.category:(app.cat||S.default_category);
  $('#devmacrow').hidden=!dev; $('#devmac').value=dev?dev.mac:'';
  $('#deverr').textContent=''; $('#devdlg').showModal(); (dev?$('#devname'):$('#devhost')).focus()}
async function saveDev(keepOpen){
  const err=$('#deverr'); err.textContent='';
  const name=$('#devname').value.trim(), host=$('#devhost').value.trim(), category=$('#devcat').value;
  if(!host){err.textContent='Informe um IP ou nome (FQDN).'; $('#devhost').focus(); return}
  $('#devsave').disabled=$('#devmore').disabled=true;
  try{
    if(app.editing){await api('/api/devices/'+app.editing,'PATCH',{name,category,mac:$('#devmac').value.trim()}); toast('Alterações salvas')}
    else{await api('/api/devices','POST',{name,host,category}); toast('Dispositivo adicionado')}
    if(keepOpen&&!app.editing){$('#devname').value='';$('#devhost').value='';$('#devhost').focus()} else $('#devdlg').close();
    load()}
  catch(e){err.textContent=e.message}
  finally{$('#devsave').disabled=$('#devmore').disabled=false}}
$('#devform').addEventListener('submit',e=>{e.preventDefault(); saveDev(false)});
$('#devmore').addEventListener('click',()=>saveDev(true));
$('#devcancel').addEventListener('click',()=>$('#devdlg').close());
$('#btn-add').addEventListener('click',()=>openDev(null));
for(const d of $$('dialog')) d.addEventListener('click',e=>{if(e.target===d) d.close()});

/* --------------------------------------------------------- lista: eventos */
$('#list').addEventListener('click',async e=>{
  if(!S) return; const t=e.target, cb=t.closest('input[data-sel]');
  if(cb){
    const id=+cb.dataset.sel, vis=visibleDevices().map(d=>d.id);
    if(e.shiftKey&&app.last!=null&&vis.includes(app.last)){   // Shift: seleciona o intervalo
      const a=vis.indexOf(app.last), b=vis.indexOf(id);
      for(const x of vis.slice(Math.min(a,b),Math.max(a,b)+1)) cb.checked?app.sel.add(x):app.sel.delete(x)}
    else cb.checked?app.sel.add(id):app.sel.delete(id);
    app.last=id; renderDevices(); return}
  const b=t.closest('[data-act]'); if(!b) return;
  const id=+b.closest('.item').dataset.k, d=S.devices.find(x=>x.id===id); if(!d) return;
  try{
    if(b.dataset.act==='expand'){app.open.has(id)?app.open.delete(id):app.open.add(id); renderDevices()}
    if(b.dataset.act==='edit') openDev(d);
    if(b.dataset.act==='check'){b.disabled=true; await api(`/api/devices/${id}/check`,'POST'); toast('Verificado: '+d.name); load()}
    if(b.dataset.act==='del'&&confirm(`Excluir “${d.name}” (${d.host}) e todo o histórico de quedas dele?`)){
      await api('/api/devices/'+id,'DELETE'); app.sel.delete(id); toast('Dispositivo excluído'); load()}
  }catch(x){toast(x.message,true); load()}});

$('#fleet').addEventListener('click',e=>{const c=e.target.closest('.cell'); if(c) focusDevice(+c.dataset.id)});
$('#selall').addEventListener('click',e=>{const vis=visibleDevices(); vis.forEach(d=>e.target.checked?app.sel.add(d.id):app.sel.delete(d.id)); renderDevices()});
$('#colhead').addEventListener('click',e=>{const b=e.target.closest('.sortbtn'); if(!b) return; const k=b.dataset.sort;
  app.sort=app.sort.k===k?{k,d:-app.sort.d}:{k,d:1}; store.set('nw_sk',app.sort.k); store.set('nw_sd',app.sort.d); renderDevices()});
$('#q').addEventListener('input',e=>{app.q=e.target.value; renderDevices()});
$('#q').addEventListener('keydown',e=>{if(e.key==='Escape'){e.target.value=''; app.q=''; renderDevices()}});
$('#seg').addEventListener('click',e=>{const b=e.target.closest('[data-st]'); if(b){app.st=b.dataset.st; renderDevices()}});
$('#cats').addEventListener('click',e=>{const b=e.target.closest('[data-cat]'); if(b){app.cat=b.dataset.cat; renderDevices()}});
$('#stats').addEventListener('click',e=>{const b=e.target.closest('[data-st]'); if(b){app.st=app.st===b.dataset.st?'':b.dataset.st; setTab('devices'); if(S) renderDevices()}});
$('#clearfilters').addEventListener('click',()=>{app.q=app.st=app.cat=''; $('#q').value=''; renderDevices()});
$('#density').addEventListener('click',()=>{app.compact=!app.compact; store.set('nw_density',app.compact?'compact':''); renderDevices()});
$('#catmanage').addEventListener('click',()=>{$('#catdlg').showModal(); renderCatList(); $('#catname').focus()});
document.addEventListener('click',e=>{
  const g=e.target.closest('[data-go]'); if(g) setTab(g.dataset.go);
  if(e.target.closest('[data-go-add]')) openDev(null)});

/* ---------------------------------------------------- ações em massa */
async function batch(action,ids,extra){for(let i=0;i<ids.length;i+=500) await api('/api/devices/batch','POST',{action,ids:ids.slice(i,i+500),...extra})}
$('#bulkapply').addEventListener('click',async()=>{const ids=[...app.sel], cat=$('#selcat').value;
  try{await batch('category',ids,{category:cat}); toast(`${ids.length} dispositivo(s) movido(s) para “${cat}”`); app.sel.clear(); load()}catch(e){toast(e.message,true)}});
$('#bulkdel').addEventListener('click',async()=>{const ids=[...app.sel];
  if(!confirm(`Excluir ${ids.length} dispositivo(s) e o histórico de quedas deles? Isso não pode ser desfeito.`)) return;
  try{await batch('delete',ids); toast(`${ids.length} dispositivo(s) excluído(s)`); app.sel.clear(); load()}catch(e){toast(e.message,true)}});
$('#bulkclear').addEventListener('click',()=>{app.sel.clear(); renderDevices()});

/* ---------------------------------------------------------- categorias */
$('#catform').addEventListener('submit',async e=>{e.preventDefault();
  try{const r=await api('/api/categories','POST',{name:$('#catname').value}); $('#catname').value=''; toast('Categoria “'+r.name+'” criada'); load()}catch(x){toast(x.message,true)}});
$('#catclose').addEventListener('click',()=>$('#catdlg').close());
$('#catlist').addEventListener('click',async e=>{const b=e.target.closest('button[data-a]'); if(!b) return; const c=b.dataset.c;
  try{
    if(b.dataset.a==='catren'){const nn=prompt('Novo nome para “'+c+'”:',c);
      if(nn&&nn.trim()&&nn.trim()!==c){const r=await api('/api/categories/rename','POST',{name:c,new_name:nn}); if(app.cat===c) app.cat=r.name; toast('Categoria renomeada'); load()}}
    if(b.dataset.a==='catdel'){const n=S.devices.filter(d=>d.category===c).length;
      if(confirm(`Excluir a categoria “${c}”?`+(n?`\n\nOs ${n} dispositivo(s) dela passam para “${S.default_category}”.`:''))){
        await api('/api/categories/delete','POST',{name:c}); if(app.cat===c) app.cat=''; toast('Categoria excluída'); load()}}
  }catch(x){toast(x.message,true)}});

/* ----------------------------------------------------------- varredura */
$('#scanform').addEventListener('submit',async e=>{e.preventDefault(); const net=$('#network').value.trim();
  try{scanSel.clear(); rowCat={}; await api('/api/scan','POST',{network:net,deep:$('#deep').checked}); store.set('nw_network',net); load()}catch(x){toast(x.message,true)}});
$('#bulkcat').addEventListener('change',()=>{lastScan=''; if(S) renderScan()});
$('#scan').addEventListener('change',e=>{const t=e.target;
  if(t.dataset.ip&&t.type==='checkbox'){t.checked?scanSel.add(t.dataset.ip):scanSel.delete(t.dataset.ip); renderScan()}
  if(t.classList.contains('rowcat')) rowCat[t.dataset.ip]=t.value;
  if(t.dataset.a==='scanall'){const fresh=S.scan.found.filter(x=>!x.registered); scanSel=t.checked?new Set(fresh.map(x=>x.ip)):new Set(); renderScan()}});
$('#scan').addEventListener('click',async e=>{const b=e.target.closest('button[data-a]'); if(!b) return; const a=b.dataset.a;
  if(a==='addsel'||a==='addall'){
    const def=$('#bulkcat').value, list=S.scan.found.filter(h=>!h.registered&&(a==='addall'||scanSel.has(h.ip)))
      .map(h=>({name:h.hostname||h.ip,host:h.ip,category:rowCat[h.ip]||h.suggested||def,mac:h.mac,vendor:h.vendor}));
    try{const r=await api('/api/devices/bulk','POST',{devices:list,category:def}); scanSel.clear();
      toast(r.added+' dispositivo(s) adicionado(s)'+(r.skipped.length?`, ${r.skipped.length} ignorado(s)`:'')); load()}catch(x){toast(x.message,true)}}});

/* ------------------------------------------------- histórico, tema, atalhos */
$('#oq').addEventListener('input',()=>S&&renderOutages());
$('#oopen').addEventListener('change',()=>S&&renderOutages());
const themeIcon=()=>{const dark=document.documentElement.dataset.theme==='dark'; $('#themebtn').innerHTML=ic(dark?'sun':'moon',18); $('#themebtn').title=dark?'Usar tema claro':'Usar tema escuro'};
$('#themebtn').addEventListener('click',()=>{const t=document.documentElement.dataset.theme==='dark'?'light':'dark'; document.documentElement.dataset.theme=t; store.set('nw_theme',t); themeIcon()});
document.addEventListener('keydown',e=>{ // "/" foca a busca
  if(e.key==='/'&&!e.ctrlKey&&!e.metaKey&&!/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)){e.preventDefault(); setTab('devices'); $('#q').focus()}});
$('.tabs').addEventListener('click',e=>{const b=e.target.closest('[data-tab]'); if(b) setTab(b.dataset.tab)});
$('.tabs').addEventListener('keydown',e=>{ // ← → navegam entre as abas
  const tabs=$$('.tabs [data-tab]'), i=tabs.findIndex(b=>b.getAttribute('aria-selected')==='true');
  if(e.key==='ArrowRight'||e.key==='ArrowLeft'){e.preventDefault(); const n=tabs[(i+(e.key==='ArrowRight'?1:tabs.length-1))%tabs.length]; setTab(n.dataset.tab); n.focus()}});

const logoutBtn=$('#logoutbtn'); if(logoutBtn) logoutBtn.addEventListener('click',async()=>{try{await api('/api/logout','POST',{})}catch(e){} location.reload()});
$$('[data-ic]').forEach(el=>{el.innerHTML=ic(el.dataset.ic,+el.dataset.s||16)});
themeIcon();
setTab(location.hash.slice(1)||store.get('nw_tab','devices'));
load();
</script>
</body>
</html>
"""


LOGIN_PAGE = r"""<!doctype html>
<html lang="pt-BR" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>NetWatch – Entrar</title>
<!--FAVICON-->
<script>try{document.documentElement.dataset.theme=localStorage.getItem('nw_theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light')}catch(e){}</script>
<style>
  :root{--ink:#15202B;--mute:#5B6B7B;--faint:#8A97A5;--paper:#F1F4F7;--sheet:#FFFFFF;--field:#FFFFFF;--line:#E0E6EC;--down:#E03E45;--down-soft:#FDECEC;--accent:#2350D8;--accent-soft:#E7EDFC;
    --mono:ui-monospace,"Cascadia Mono",Consolas,Menlo,monospace;--sans:"Segoe UI Variable","Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif}
  :root[data-theme=dark]{--ink:#E6EDF3;--mute:#9AA9B8;--faint:#6F7E8D;--paper:#0F151B;--sheet:#171F27;--field:#1D2833;--line:#293541;--down:#FF6B72;--down-soft:#3A1E23;--accent:#7B9BFF;--accent-soft:#1E2B4F;color-scheme:dark}
  *{box-sizing:border-box}
  html{background:var(--paper)}
  body{margin:0;min-height:100vh;display:grid;place-items:center;color:var(--ink);font:15px/1.45 var(--sans);-webkit-font-smoothing:antialiased;padding:16px}
  .card{background:var(--sheet);border:1px solid var(--line);border-radius:18px;box-shadow:0 12px 40px rgba(16,24,40,.10);padding:34px 30px 26px;width:min(410px,100%);text-align:center}
  .brand{display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:6px}
  .logo{height:60px;width:auto;max-width:180px;object-fit:contain;display:block}
  h1{margin:0;font-size:26px;letter-spacing:-.02em}
  .lead{margin:6px 0 26px;color:var(--mute)}
  .pin{display:flex;gap:12px;justify-content:center}
  .pin input{width:60px;height:70px;text-align:center;font:600 30px var(--mono);color:var(--ink);background:var(--field);border:1.5px solid var(--line);border-radius:14px;padding:0;caret-color:var(--accent)}
  .pin input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-soft)}
  .pin.err input{border-color:var(--down)} .pin input:disabled{opacity:.55}
  @keyframes shake{10%,90%{transform:translateX(-2px)}20%,80%{transform:translateX(4px)}30%,50%,70%{transform:translateX(-7px)}40%,60%{transform:translateX(7px)}}
  @media (prefers-reduced-motion:no-preference){.pin.shake{animation:shake .38s}}
  .msg{min-height:1.5em;margin:18px 0 0;color:var(--down);font-size:14px;font-weight:600}
  .msg.info{color:var(--mute);font-weight:400}
  .show{margin-top:10px;background:none;border:0;color:var(--mute);font:inherit;font-size:13px;cursor:pointer;text-decoration:underline;text-underline-offset:3px}
  .foot{margin-top:18px;font-size:12px;color:var(--faint)}
  :focus-visible{outline:2px solid var(--accent);outline-offset:2px}
  @media (max-width:380px){.pin{gap:8px}.pin input{width:52px;height:62px;font-size:26px}}
</style>
</head>
<body>
<main class="card">
  <div class="brand"><!--LOGO--><h1>NetWatch</h1></div>
  <p class="lead">Digite o código de acesso de 4 números</p>
  <form id="f" novalidate>
    <div class="pin" id="pin" role="group" aria-label="Código de acesso de 4 dígitos">
      <input type="password" inputmode="numeric" pattern="[0-9]*" maxlength="1" autocomplete="one-time-code" aria-label="Dígito 1" autofocus>
      <input type="password" inputmode="numeric" pattern="[0-9]*" maxlength="1" autocomplete="off" aria-label="Dígito 2">
      <input type="password" inputmode="numeric" pattern="[0-9]*" maxlength="1" autocomplete="off" aria-label="Dígito 3">
      <input type="password" inputmode="numeric" pattern="[0-9]*" maxlength="1" autocomplete="off" aria-label="Dígito 4">
    </div>
    <p class="msg" id="msg" role="alert" aria-live="assertive"></p>
    <button type="button" class="show" id="show">Mostrar código</button>
  </form>
  <noscript><p class="msg">Ative o JavaScript para entrar.</p></noscript>
  <div class="foot">Acesso restrito</div>
</main>
<script>
'use strict';
const $=s=>document.querySelector(s), boxes=[...document.querySelectorAll('#pin input')], msg=$('#msg'), pin=$('#pin');
let busy=false, lockTimer=null;
const code=()=>boxes.map(b=>b.value).join('');
function clear(focus){boxes.forEach(b=>b.value=''); if(focus) boxes[0].focus()}
function setMsg(t,info){msg.textContent=t||''; msg.className='msg'+(info?' info':'')}
function fail(text){pin.classList.remove('shake'); void pin.offsetWidth; pin.classList.add('err','shake'); setMsg(text); clear(true)}
function lock(seconds){
  boxes.forEach(b=>b.disabled=true); clearInterval(lockTimer); let left=seconds;
  const tick=()=>{const m=Math.floor(left/60), s=String(left%60).padStart(2,'0'); setMsg(`Muitas tentativas. Tente novamente em ${m}:${s}.`);
    if(left--<=0){clearInterval(lockTimer); boxes.forEach(b=>b.disabled=false); pin.classList.remove('err'); setMsg(''); boxes[0].focus()}};
  tick(); lockTimer=setInterval(tick,1000)}
async function submit(){
  if(busy||code().length<4) return; busy=true; pin.classList.remove('err'); setMsg('Verificando…',true); boxes.forEach(b=>b.disabled=true);
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin:code()})});
    const j=await r.json().catch(()=>({}));
    if(r.ok){setMsg('Entrando…',true); location.reload(); return}
    boxes.forEach(b=>b.disabled=false);
    if(r.status===429){clear(false); pin.classList.add('err'); lock(j.retry||60)} else fail(j.error||'Código incorreto.')}
  catch(e){boxes.forEach(b=>b.disabled=false); fail('Sem conexão com o servidor.')}
  finally{busy=false}}
boxes.forEach((b,i)=>{
  b.addEventListener('input',()=>{b.value=b.value.replace(/\D/g,'').slice(-1); pin.classList.remove('err'); if(b.value&&i<3) boxes[i+1].focus(); if(code().length===4) submit()});
  b.addEventListener('keydown',e=>{
    if(e.key==='Backspace'&&!b.value&&i>0){e.preventDefault(); boxes[i-1].value=''; boxes[i-1].focus()}
    if(e.key==='ArrowLeft'&&i>0){e.preventDefault(); boxes[i-1].focus()}
    if(e.key==='ArrowRight'&&i<3){e.preventDefault(); boxes[i+1].focus()}});
  b.addEventListener('paste',e=>{const d=(e.clipboardData.getData('text')||'').replace(/\D/g,'').slice(0,4); if(!d) return; e.preventDefault();
    d.split('').forEach((c,k)=>boxes[k].value=c); boxes[Math.min(d.length,3)].focus(); if(d.length===4) submit()});
  b.addEventListener('focus',()=>b.select())});
$('#f').addEventListener('submit',e=>{e.preventDefault(); submit()});
$('#show').addEventListener('click',e=>{const show=boxes[0].type==='password'; boxes.forEach(b=>b.type=show?'text':'password'); e.target.textContent=show?'Ocultar código':'Mostrar código'});
</script>
</body>
</html>
"""


def _brand():
    """Logo (LOGO_URL) e ícone da aba. Sem LOGO_URL o logo não é exibido."""
    if LOGO_URL.strip():
        url = _attr(LOGO_URL.strip(), quote=True)
        logo = '<img class="logo" src="%s" alt="Logo" onerror="this.remove()">' % url
        fav = '<link rel="icon" href="%s">' % url
    else:  # ícone simples para o navegador não pedir /favicon.ico
        logo = ""
        fav = ('<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 '
               'viewBox=%270 0 32 32%27%3E%3Ccircle cx=%2716%27 cy=%2716%27 r=%2712%27 fill=%27%230e9f6e%27/%3E%3C/svg%3E">')
    return logo, fav


def render_page():
    logo, fav = _brand()
    logout = ('<button class="ib lg" id="logoutbtn" type="button" aria-label="Sair" title="Sair">'
              '<span data-ic="logout" data-s="18"></span></button>') if PANEL_PIN else ""
    return PAGE.replace("<!--LOGO-->", logo).replace("<!--FAVICON-->", fav).replace("<!--LOGOUT-->", logout)


def render_login():
    logo, fav = _brand()
    return LOGIN_PAGE.replace("<!--LOGO-->", logo).replace("<!--FAVICON-->", fav)


_lock_file = None


def acquire_instance_lock():
    """Impede duas cópias do NetWatch usando o mesmo banco: uma delas, mais antiga, poderia sobrescrever o status."""
    global _lock_file
    f = open(DB_FILE + ".lock", "a+")
    try:
        f.seek(0)
        if WIN:
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return False
    f.seek(0)
    f.truncate()
    f.write(str(os.getpid()))
    f.flush()
    _lock_file = f
    return True


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    if not acquire_instance_lock():
        sys.exit("Já existe outro NetWatch usando este banco (%s). Feche-o antes (ex.: ps aux | grep netwatch)." % DB_FILE)
    if PANEL_PIN and not re.fullmatch(r"\d{4}", PANEL_PIN):
        sys.exit('PANEL_PIN precisa ter exatamente 4 números (ex.: "0308"), ou ficar vazio para desativar o login.')
    if not PANEL_PIN:
        log.warning("Login DESATIVADO (PANEL_PIN vazio): qualquer pessoa na rede acessa o painel.")
    elif PANEL_PIN == "0308":
        log.warning('Você está usando o código de exemplo (0308). Troque PANEL_PIN no topo do arquivo.')
    threading.Thread(target=monitor_loop, daemon=True).start()
    threading.Thread(target=sn_loop, daemon=True).start()
    threading.Thread(target=tg_worker, daemon=True).start()
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    srv.daemon_threads = True
    log.info("NetWatch rodando em http://localhost:%d", PORT)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("Encerrando.")


if __name__ == "__main__":
    main()
