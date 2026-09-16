#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# NetGate -- controle d'acces Internet par application (Windows)
# Copyright (C) 2026 ETDEL
#
# Ce programme est un logiciel libre : vous pouvez le redistribuer et/ou le
# modifier selon les termes de la GNU General Public License telle que
# publiee par la Free Software Foundation, soit la version 3 de la licence,
# soit (a votre choix) toute version ulterieure.
#
# Ce programme est distribue dans l'espoir qu'il sera utile, mais SANS
# AUCUNE GARANTIE, sans meme la garantie implicite de QUALITE MARCHANDE ou
# d'ADEQUATION A UN USAGE PARTICULIER. Voir la GNU General Public License
# pour plus de details.
#
# Vous devriez avoir recu une copie de la GNU General Public License avec ce
# programme (fichier LICENSE). Sinon, voir <https://www.gnu.org/licenses/>.
"""
NetGate - Controle d'acces Internet par application (Windows)
=============================================================
Principe : le robinet Internet est ferme, tu l'ouvres application par
application. NetGate compte ce que chacune consomme et te previent quand
l'enveloppe du jour s'epuise, sans jamais rien couper de lui-meme.

L'application vit dans la zone de notification (a cote de l'horloge). Des
qu'un programme essaie d'aller sur Internet, une petite fenetre apparait en
bas a droite avec deux boutons : Autoriser / Bloquer.

Installation :
    pip install psutil pywintrace pystray pillow
Lancement (administrateur obligatoire) :
    python netgate.py

ETDEL (c) 2026

Historique des versions
-----------------------
V1.0  Version initiale : filtrage par application via le pare-feu Windows,
      comptage ETW par processus, enveloppe journaliere avec alertes,
      notifications d'autorisation, icone dans la zone de notification,
      profils facultatifs, aide integree (F1).
V1.1  Numero de version affiche dans le titre, la barre d'etat et l'aide.
      Remise a zero du compteur deplacee dans les reglages.
V1.2  L'enveloppe n'est decomptee que lorsque la protection est active ;
      hors protection le trafic est mesure mais affiche a part. Trace de la
      remise a zero au demarrage. Bascule forcee si l'horloge a recule.
V1.3  Plages horaires : tableau de 48 demi-heures dans les reglages, hors
      plage plus aucun programme ne sort.
"""

import ctypes
import hashlib
import json
import os
import queue
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# --------------------------------------------------------------------------
# Dependances optionnelles (l'application demarre meme sans elles)
# --------------------------------------------------------------------------
try:
    import psutil
except ImportError:
    psutil = None

try:
    import etw as _etw
    from etw.GUID import GUID as _GUID
except Exception:
    _etw = None
    _GUID = None

try:
    from PIL import Image, ImageDraw
except Exception:
    Image = None
    ImageDraw = None

try:
    import pystray
except Exception:
    pystray = None


# ==========================================================================
#  CONSTANTES
# ==========================================================================

APP_NAME = "NetGate"

# ---------------------------------------------------------------------------
#  Identite du logiciel : ces trois lignes alimentent le bas de la fenetre,
#  l'aide (F1) et l'en-tete du fichier.
# ---------------------------------------------------------------------------
AUTEUR = "ETDEL"
ANNEE = "2026"

# Numerotation : V<majeure>.<mineure>, plus une lettre pour une retouche
# mineure (V1.1a). La majeure change en cas de refonte, la mineure a chaque
# ajout ou correction, la lettre pour un ajustement cosmetique.
VERSION = "1.3"

VERSION_TXT = "V" + VERSION
COPYRIGHT = "%s \u00a9 %s" % (AUTEUR, ANNEE)

__author__ = AUTEUR
__copyright__ = COPYRIGHT
__version__ = VERSION

RULE_PREFIX = "NETGATE_"
CREATE_NO_WINDOW = 0x08000000

KERNEL_NETWORK_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
ETW_SENT_IDS = {10, 26, 42, 58}
ETW_RECV_IDS = {11, 27, 43, 59}

C_BG      = "#16181d"
C_PANEL   = "#1e2128"
C_PANEL2  = "#252933"
C_LINE    = "#333844"
C_TXT     = "#e6e9ef"
C_TXT_DIM = "#8b93a5"
C_ACCENT  = "#4da3ff"
C_OK      = "#3ecf8e"
C_WARN    = "#ffb020"
C_DANGER  = "#ff5c5c"

def _base_dir():
    """Dossier du script (ou de l'executable si le programme est compile)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return os.path.dirname(os.path.abspath(sys.argv[0] or "."))


def _choose_state_dir():
    """Les fichiers sont ranges a cote de netgate.py. Si ce dossier n'est pas
    inscriptible (Program Files, cle USB protegee, dossier reseau), on se
    rabat sur %APPDATA% pour que le programme fonctionne quand meme."""
    local = _base_dir()
    try:
        os.makedirs(local, exist_ok=True)
        test = os.path.join(local, ".netgate_test")
        with open(test, "w") as f:
            f.write("ok")
        os.remove(test)
        return local
    except Exception:
        return os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP_NAME)


STATE_DIR = _choose_state_dir()
STATE_FILE = os.path.join(STATE_DIR, "netgate.state.json")
LOG_FILE = os.path.join(STATE_DIR, "netgate.log")
ICO_PATH = os.path.join(STATE_DIR, "netgate.ico")
LEGACY_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP_NAME)


def log_line(txt):
    """Ecrit dans %APPDATA%\\NetGate\\netgate.log. Sert a diagnostiquer quand la
    console se referme avant qu'on ait pu lire quoi que ce soit."""
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), txt))
    except Exception:
        pass


def log_error(contexte, exc_info=None):
    """Ecrit l'erreur dans %APPDATA%\\NetGate\\netgate.log. Sans ca, une fenetre
    lancee en administrateur disparait sans laisser de trace."""
    import traceback
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("\n%s  ---  %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), contexte))
            f.write("Python %s\n" % sys.version.split()[0])
            traceback.print_exception(*(exc_info or sys.exc_info()), file=f)
    except Exception:
        pass

DEFAULT_PROFILES = {
    "defaut": {
        "name": "Mes autorisations",
        "color": C_ACCENT,
        "desc": "Liste unique des programmes autorises.",
        "budget_mb": 0,
        "allow_all": False,
        "apps": {},
    },
}

# Modeles proposes dans les reglages pour qui veut plusieurs profils.
PRESET_PROFILES = {
    "Blackout": ("#ff5c5c", "Rien ne sort. Aucune application n'a acces a Internet.",
                 0, False),
    "Essentiel": ("#3ecf8e", "Messagerie et navigation legere. Consommation minimale.",
                  100, False),
    "Travail": ("#4da3ff", "Outils metier, transferts de fichiers, navigateur.",
                250, False),
    "Visio": ("#c58bff", "Appels video. Gros consommateur, a surveiller.", 150, False),
    "Libre": ("#ffb020", "Aucun filtrage. Tout passe, le compteur tourne quand meme.",
              0, True),
}


def slugify(name):
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return s or ("profil-%d" % int(time.time()))

DEFAULT_STATE = {
    "schema": 2,
    "quota_mb": 500,
    "reset_hh": 0,
    "reset_mm": 0,
    "tz_mode": "local",
    "alert_pct": [50, 80, 100],
    "schedule_enabled": False,
    "schedule": "1" * 48,          # 48 demi-heures, 1 = Internet autorise
    "essentials_dns": True,
    "notify_enabled": True,
    "notify_timeout": 25,
    "start_minimized": False,
    "active_profile": "essentiel",
    "profiles": DEFAULT_PROFILES,
    "catalog": {},
    "usage": {"period": "", "per_app": {}, "per_profile": {}, "per_hour": {},
              "total_sent": 0, "total_recv": 0, "off_sent": 0, "off_recv": 0},
    "history": {},
    "alerts_fired": [],
    "engaged": False,
}


# ==========================================================================
#  UTILITAIRES
# ==========================================================================

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    params = " ".join('"%s"' % a for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)


def fmt_bytes(n):
    n = float(n or 0)
    for unit, div in (("Go", 1024 ** 3), ("Mo", 1024 ** 2), ("Ko", 1024.0)):
        if n >= div:
            return "%.1f %s" % (n / div, unit)
    return "%d o" % int(n)


def run_netsh(args, timeout=15):
    try:
        p = subprocess.run(["netsh"] + args, capture_output=True, text=True,
                           timeout=timeout, creationflags=CREATE_NO_WINDOW,
                           shell=False, errors="ignore")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return -1, str(e)


def proc_connections(proc, kind="inet"):
    """psutil 6 a renomme Process.connections() en net_connections().
    On utilise le nouveau nom quand il existe, sans casser les anciennes
    versions."""
    fn = getattr(proc, "net_connections", None) or proc.connections
    return fn(kind=kind)


def rule_name_for(path):
    h = hashlib.sha1(path.lower().encode("utf-8", "ignore")).hexdigest()[:14]
    return RULE_PREFIX + "OUT_" + h


def now_in(tz_mode):
    return datetime.now(timezone.utc) if tz_mode == "utc" else datetime.now()


# ==========================================================================
#  PARE-FEU WINDOWS
# ==========================================================================

class Firewall:
    """Toutes les regles creees sont prefixees NETGATE_. Les regles tierces
    ne sont jamais touchees.

    Chaque appel a netsh coute environ 200 ms. Pour ne pas figer l'interface
    a chaque changement de profil, toutes les modifications sont regroupees
    dans un script execute en une seule fois (netsh -f)."""

    ESS_NAMES = (RULE_PREFIX + "ESS_DNS_UDP", RULE_PREFIX + "ESS_DNS_TCP",
                 RULE_PREFIX + "ESS_DHCP")

    # ------------------------------------------------- fabrication des lignes
    @staticmethod
    def line_allow(path, label=""):
        name = rule_name_for(path)
        return ['advfirewall firewall delete rule name=%s' % name,
                'advfirewall firewall add rule name=%s dir=out action=allow '
                'program="%s" enable=yes profile=any description="NetGate %s"'
                % (name, path, (label or os.path.basename(path))[:60])]

    @staticmethod
    def line_delete(path):
        return ['advfirewall firewall delete rule name=%s' % rule_name_for(path)]

    @staticmethod
    def line_lockdown(enable):
        policy = "blockinbound,blockoutbound" if enable else "blockinbound,allowoutbound"
        return ['advfirewall set allprofiles firewallpolicy %s' % policy]

    @staticmethod
    def lines_essentials(enable):
        lines = ['advfirewall firewall delete rule name=%s' % n
                 for n in Firewall.ESS_NAMES]
        if not enable:
            return lines
        svchost = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                               "System32", "svchost.exe")
        for name, proto, ports in ((Firewall.ESS_NAMES[0], "udp", "53"),
                                   (Firewall.ESS_NAMES[1], "tcp", "53"),
                                   (Firewall.ESS_NAMES[2], "udp", "67,68")):
            lines.append('advfirewall firewall add rule name=%s dir=out action=allow '
                         'program="%s" protocol=%s remoteport=%s enable=yes '
                         'profile=any description="NetGate essentiels reseau"'
                         % (name, svchost, proto, ports))
        return lines

    # ------------------------------------------------------------- execution
    @staticmethod
    def run_script(lines):
        """Execute toutes les commandes en un seul processus netsh."""
        lines = [l for l in lines if l]
        if not lines:
            return True
        fichier = os.path.join(tempfile.gettempdir(),
                               "netgate_%d_%d.netsh" % (os.getpid(), int(time.time() * 1000)))
        try:
            # netsh lit ses scripts dans l'encodage local de la machine
            with open(fichier, "w", encoding="mbcs", errors="replace") as f:
                f.write("\n".join(lines) + "\n")
        except Exception:
            return Firewall._run_one_by_one(lines)
        rc, out = run_netsh(["-f", fichier], timeout=90)
        try:
            os.remove(fichier)
        except Exception:
            pass
        if rc != 0:
            log_line("netsh -f a echoue (%s), repli commande par commande" % rc)
            return Firewall._run_one_by_one(lines)
        return True

    @staticmethod
    def _run_one_by_one(lines):
        """Repli si le script echoue : chemin non representable en encodage
        local, par exemple. Les valeurs entre guillemets (chemins avec
        espaces) doivent rester solidaires de leur mot-cle."""
        ok = True
        for l in lines:
            args = []
            for morceau in re.findall(r'\S*?"[^"]*"|\S+', l):
                args.append(morceau.replace('"', ''))
            rc, _ = run_netsh(args)
            ok = ok and rc == 0
        return ok

    # ------------------------------------------------- raccourcis historiques
    @staticmethod
    def set_lockdown(enable):
        return Firewall.run_script(Firewall.line_lockdown(enable)), ""

    @staticmethod
    def allow_program(path, label=""):
        return Firewall.run_script(Firewall.line_allow(path, label)), ""

    @staticmethod
    def block_program(path):
        return Firewall.run_script(Firewall.line_delete(path)), ""

    @staticmethod
    def set_essentials_dns(enable):
        return Firewall.run_script(Firewall.lines_essentials(enable)), ""

    @staticmethod
    def purge(paths):
        lines = []
        for p in paths:
            lines += Firewall.line_delete(p)
        lines += Firewall.lines_essentials(False)
        return Firewall.run_script(lines)

    @staticmethod
    def panic_restore(paths):
        lines = list(Firewall.line_lockdown(False))
        for p in paths:
            lines += Firewall.line_delete(p)
        lines += Firewall.lines_essentials(False)
        return Firewall.run_script(lines)


# ==========================================================================
#  COMPTEUR ETW
# ==========================================================================

class EtwMeter(threading.Thread):
    daemon = True

    def __init__(self):
        super().__init__(name="EtwMeter")
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._acc = {}
        self.mode = "init"
        self.error = ""
        self._job = None
        self._fb_base = None

    def drain(self):
        with self._lock:
            data, self._acc = self._acc, {}
        return data

    def stop(self):
        self._stop.set()

    def _add(self, pid, sent, recv):
        with self._lock:
            slot = self._acc.setdefault(pid, [0, 0])
            slot[0] += sent
            slot[1] += recv

    @staticmethod
    def _pick(payload, keys):
        for k in keys:
            if k in payload:
                v = payload[k]
                try:
                    if isinstance(v, str):
                        v = v.strip()
                        return int(v, 16) if v.lower().startswith("0x") else int(v)
                    return int(v)
                except (TypeError, ValueError):
                    continue
        return None

    def _callback(self, event):
        try:
            event_id, payload = event[0], event[1]
        except Exception:
            return
        if not isinstance(payload, dict):
            return
        if event_id not in ETW_SENT_IDS and event_id not in ETW_RECV_IDS:
            return
        pid = self._pick(payload, ("PID", "pid", "ProcessId"))
        size = self._pick(payload, ("size", "Size", "TransferSize", "DataLength"))
        if pid is None or not size or size <= 0:
            return
        if event_id in ETW_SENT_IDS:
            self._add(pid, size, 0)
        else:
            self._add(pid, 0, size)

    def run(self):
        if _etw is not None and _GUID is not None:
            try:
                providers = [_etw.ProviderInfo("Microsoft-Windows-Kernel-Network",
                                               _GUID(KERNEL_NETWORK_GUID))]
                self._job = _etw.ETW(providers=providers, event_callback=self._callback)
                self._job.start()
                self.mode = "etw"
            except Exception as e:
                self.mode = "global"
                self.error = str(e)
        else:
            self.mode = "global"
            self.error = "pywintrace absent"
        while not self._stop.is_set():
            if self.mode == "global":
                self._fb_tick()
            time.sleep(1.0)
        if self._job is not None:
            try:
                self._job.stop()
            except Exception:
                pass

    def _fb_tick(self):
        if psutil is None:
            return
        try:
            c = psutil.net_io_counters()
        except Exception:
            return
        cur = (c.bytes_sent, c.bytes_recv)
        if self._fb_base is None:
            self._fb_base = cur
            return
        ds = max(0, cur[0] - self._fb_base[0])
        dr = max(0, cur[1] - self._fb_base[1])
        self._fb_base = cur
        if ds or dr:
            self._add(0, ds, dr)


# ==========================================================================
#  DETECTION DES TENTATIVES
# ==========================================================================

class ConnScanner(threading.Thread):
    daemon = True

    def __init__(self, decided_getter, out_queue, interval=1.5):
        super().__init__(name="ConnScanner")
        self._stop = threading.Event()
        self.decided = decided_getter
        self.q = out_queue
        self.interval = interval
        self.pid_cache = {}
        self.asked = set()

    def stop(self):
        self._stop.set()

    def forget(self, path):
        self.asked.discard(path.lower())

    def reset_asked(self):
        self.asked.clear()

    def exe_for(self, pid):
        if pid in self.pid_cache:
            return self.pid_cache[pid]
        exe = None
        try:
            exe = psutil.Process(pid).exe()
        except Exception:
            try:
                exe = psutil.Process(pid).name()
            except Exception:
                exe = None
        if exe:
            self.pid_cache[pid] = exe
        return exe

    def run(self):
        if psutil is None:
            return
        while not self._stop.is_set():
            try:
                conns = psutil.net_connections(kind="inet")
            except Exception:
                conns = []
            pids = {c.pid for c in conns if c.pid and c.status != "LISTEN"}
            for pid in pids:
                exe = self.exe_for(pid)
                if not exe:
                    continue
                key = exe.lower()
                if key in self.decided() or key in self.asked:
                    continue
                self.asked.add(key)
                self.q.put({"path": exe, "pid": pid, "ts": time.time()})
            if len(self.pid_cache) > 4000:
                self.pid_cache.clear()
            self._stop.wait(self.interval)


# ==========================================================================
#  ETAT
# ==========================================================================

class State:
    def __init__(self):
        self.data = json.loads(json.dumps(DEFAULT_STATE))
        self.load()

    def load(self):
        # reprise d'une configuration creee par les versions precedentes,
        # qui rangeaient tout dans %APPDATA%\NetGate
        if not os.path.exists(STATE_FILE) and STATE_DIR != LEGACY_DIR:
            for ancien in ("state.json", "netgate.state.json"):
                src = os.path.join(LEGACY_DIR, ancien)
                if os.path.exists(src):
                    try:
                        os.makedirs(STATE_DIR, exist_ok=True)
                        with open(src, "r", encoding="utf-8") as f_in, \
                                open(STATE_FILE, "w", encoding="utf-8") as f_out:
                            f_out.write(f_in.read())
                        log_line("configuration reprise depuis %s" % src)
                    except Exception:
                        pass
                    break

        disk = {}
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                disk = json.load(f)
            for k, v in disk.items():
                if k in DEFAULT_STATE:
                    self.data[k] = v
        except Exception:
            disk = {}
        # un fichier existant sans numero de schema vient d'avant la
        # simplification : il faut le migrer
        schema = disk.get("schema", 1) if disk else 2
        if not self.data.get("profiles"):
            self.data["profiles"] = json.loads(json.dumps(DEFAULT_PROFILES))

        # Migration : les anciennes versions imposaient cinq profils. On les
        # fond en une liste unique, sans perdre les autorisations deja donnees.
        if schema < 2:
            legacy = {"blackout", "essentiel", "travail", "visio", "libre"}
            ids = set(self.data["profiles"].keys())
            if ids and ids <= legacy:
                fusion = {}
                for pid in ids:
                    fusion.update(self.data["profiles"][pid].get("apps", {}))
                self.data["profiles"] = json.loads(json.dumps(DEFAULT_PROFILES))
                self.data["profiles"]["defaut"]["apps"] = fusion
                self.data["active_profile"] = "defaut"
                self.data["usage"]["per_profile"] = {}
                log_line("migration : %d anciens profils fondus en une liste unique "
                         "(%d autorisations conservees)" % (len(ids), len(fusion)))
            self.data["schema"] = 2

        for prof in self.data["profiles"].values():
            for field, val in (("name", "Profil"), ("color", C_ACCENT), ("desc", ""),
                               ("budget_mb", 0), ("allow_all", False), ("apps", {})):
                prof.setdefault(field, val)
        if self.data["active_profile"] not in self.data["profiles"]:
            self.data["active_profile"] = list(self.data["profiles"].keys())[0]

    def profile_ids(self):
        return list(self.data["profiles"].keys())

    def multi_profiles(self):
        return len(self.data["profiles"]) > 1

    def save(self):
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            tmp = STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            os.replace(tmp, STATE_FILE)
        except Exception as e:
            print("Sauvegarde impossible :", e)

    # -- profils -----------------------------------------------------------
    @property
    def profile(self):
        return self.data["profiles"][self.data["active_profile"]]

    def profile_name(self, pid=None):
        return self.data["profiles"][pid or self.data["active_profile"]]["name"]

    def profile_color(self, pid=None):
        return self.data["profiles"][pid or self.data["active_profile"]]["color"]

    def decided_paths(self):
        """Applications deja tranchees pour le profil actif (oui ou non)."""
        if self.profile.get("allow_all"):
            return set()
        return set(self.profile["apps"].keys())

    def allowed_paths(self):
        return {p for p, v in self.profile["apps"].items() if v}

    def set_app(self, path, allow):
        self.profile["apps"][path.lower()] = bool(allow)
        self.data["catalog"].setdefault(path.lower(),
                                        {"name": os.path.basename(path),
                                         "first_seen": time.time()})

    def forget_app(self, path):
        self.profile["apps"].pop(path.lower(), None)

    # -- periode -----------------------------------------------------------
    def period_key(self, ref=None):
        d = self.data
        now = ref or now_in(d["tz_mode"])
        reset = now.replace(hour=int(d["reset_hh"]), minute=int(d["reset_mm"]),
                            second=0, microsecond=0)
        day = now.date() if now >= reset else (now - timedelta(days=1)).date()
        return day.isoformat()

    def next_reset(self):
        d = self.data
        now = now_in(d["tz_mode"])
        reset = now.replace(hour=int(d["reset_hh"]), minute=int(d["reset_mm"]),
                            second=0, microsecond=0)
        if reset <= now:
            reset += timedelta(days=1)
        return reset - now

    def roll_period_if_needed(self):
        """Bascule si la date de remise a zero est passee, y compris apres une
        extinction prolongee du poste : la comparaison porte sur la periode
        calculee maintenant, pas sur un minuteur en memoire. Une periode
        enregistree dans le futur (horloge reculee) declenche aussi la
        bascule, sinon le compteur resterait fige."""
        key = self.period_key()
        u = self.data["usage"]
        if u.get("period") == key:
            return False
        if u.get("period", "") > key:
            log_line("periode enregistree (%s) posterieure a aujourd'hui (%s) : "
                     "remise a zero" % (u.get("period"), key))
        if u.get("period"):
            top = sorted(u.get("per_app", {}).items(),
                         key=lambda kv: -(kv[1]["sent"] + kv[1]["recv"]))[:25]
            self.data["history"][u["period"]] = {
                "total": u.get("total_sent", 0) + u.get("total_recv", 0),
                "per_profile": dict(u.get("per_profile", {})),
                "per_app": {k: v["sent"] + v["recv"] for k, v in top},
                "per_hour": dict(u.get("per_hour", {})),
            }
            for old in sorted(self.data["history"].keys())[:-60]:
                del self.data["history"][old]
        self.data["usage"] = {"period": key, "per_app": {}, "per_profile": {},
                              "per_hour": {}, "total_sent": 0, "total_recv": 0,
                              "off_sent": 0, "off_recv": 0}
        self.data["alerts_fired"] = []
        return True

    def total_used(self):
        u = self.data["usage"]
        return u.get("total_sent", 0) + u.get("total_recv", 0)

    def off_used(self):
        """Volume observe hors protection : affiche, mais hors enveloppe."""
        u = self.data["usage"]
        return u.get("off_sent", 0) + u.get("off_recv", 0)

    # ----------------------------------------------------- plages horaires
    def schedule(self):
        """48 caracteres, un par demi-heure : '1' = Internet autorise."""
        s = str(self.data.get("schedule") or "")
        if len(s) != 48 or set(s) - {"0", "1"}:
            s = "1" * 48
            self.data["schedule"] = s
        return s

    @staticmethod
    def slot_index(now):
        return now.hour * 2 + (0 if now.minute < 30 else 1)

    @staticmethod
    def slot_label(index):
        return "%02dh%02d" % (index // 2, 30 * (index % 2))

    def schedule_open(self, ref=None):
        if not self.data.get("schedule_enabled"):
            return True
        now = ref or now_in(self.data["tz_mode"])
        return self.schedule()[self.slot_index(now)] == "1"

    def schedule_next_change(self):
        """(prochain_etat, 'HH:MM') ou None si la plage ne change jamais."""
        if not self.data.get("schedule_enabled"):
            return None
        s = self.schedule()
        now = now_in(self.data["tz_mode"])
        i = self.slot_index(now)
        courant = s[i]
        for k in range(1, 49):
            j = (i + k) % 48
            if s[j] != courant:
                return (s[j] == "1", "%02d:%02d" % (j // 2, 30 * (j % 2)))
        return None

    def schedule_hours(self):
        return self.schedule().count("1") / 2.0

    def quota_bytes(self):
        return max(1, int(self.data["quota_mb"])) * 1024 * 1024

    def add_usage(self, path, sent, recv, label=None, compte=True):
        """compte=False : le volume est mesure et attribue a l'application,
        mais il n'entame pas l'enveloppe. C'est le cas quand la protection
        est desactivee : NetGate observe sans decompter."""
        u = self.data["usage"]
        if compte:
            u["total_sent"] += sent
            u["total_recv"] += recv
        else:
            u["off_sent"] = u.get("off_sent", 0) + sent
            u["off_recv"] = u.get("off_recv", 0) + recv
        key = (path or "inconnu").lower()
        slot = u["per_app"].setdefault(key, {"sent": 0, "recv": 0,
                                             "name": os.path.basename(key) or key})
        slot["sent"] += sent
        slot["recv"] += recv
        cat = self.data["catalog"].setdefault(key, {"name": os.path.basename(key) or key,
                                                    "first_seen": time.time()})
        cat["lifetime"] = cat.get("lifetime", 0) + sent + recv
        if label:
            cat["label"] = label
        h = "%02d" % now_in(self.data["tz_mode"]).hour
        per_hour = u.setdefault("per_hour", {})
        per_hour[h] = per_hour.get(h, 0) + sent + recv
        if compte:
            pid = self.data["active_profile"]
            u["per_profile"][pid] = u["per_profile"].get(pid, 0) + sent + recv


# ==========================================================================
#  INSPECTEUR : "c'est quoi, ce programme ?"
# ==========================================================================

# Glossaire en francais des processus courants. Chaque entree :
#   (titre lisible, explication, conseil, criticite)
# criticite : "systeme" (ne pas bloquer), "utile", "gourmand" (candidat au blocage)
GLOSSARY = {
    "svchost.exe": ("Service interne de Windows",
                    "Boite qui heberge plusieurs services Windows a la fois. Ce qu'il "
                    "fait depend du service qu'il porte (voir Details).",
                    "Necessaire pour le reseau. A laisser passer.", "systeme"),
    "services.exe": ("Gestionnaire de services Windows",
                     "Chef d'orchestre des services du systeme.",
                     "Composant Windows.", "systeme"),
    "lsass.exe": ("Securite et mots de passe Windows",
                  "Gere les ouvertures de session et l'authentification.",
                  "Composant Windows.", "systeme"),
    "system": ("Noyau de Windows",
               "Trafic reseau gere directement par le systeme (partage de fichiers, "
               "impression reseau).", "Composant Windows.", "systeme"),
    "explorer.exe": ("Explorateur de fichiers / Bureau",
                     "Le bureau, la barre des taches et les fenetres de dossiers.",
                     "Consomme peu, sauf vignettes en ligne.", "utile"),
    "wuauclt.exe": ("Mise a jour Windows",
                    "Telecharge les mises a jour de Windows.",
                    "Tres gourmand. A bloquer si l'enveloppe est serree.", "gourmand"),
    "usoclient.exe": ("Mise a jour Windows (planificateur)",
                      "Declenche les recherches de mises a jour.",
                      "A bloquer si l'enveloppe est serree.", "gourmand"),
    "mousocoreworker.exe": ("Mise a jour Windows (moteur)",
                            "Cherche et prepare les mises a jour de Windows.",
                            "Tres gourmand. A bloquer si l'enveloppe est serree.",
                            "gourmand"),
    "trustedinstaller.exe": ("Installation de mises a jour Windows",
                             "Installe les composants telecharges.",
                             "Peut declencher de gros telechargements.", "gourmand"),
    "compattelrunner.exe": ("Telemetrie de compatibilite Microsoft",
                            "Envoie a Microsoft des donnees sur ton materiel et tes "
                            "logiciels.", "Aucun interet pour toi. Blocage sans risque.",
                            "gourmand"),
    "dmclient.exe": ("Telemetrie Microsoft",
                     "Envoie des statistiques d'utilisation a Microsoft.",
                     "Blocage sans risque.", "gourmand"),
    "searchapp.exe": ("Recherche Windows / Bing",
                      "La loupe de la barre des taches, qui interroge Bing en ligne.",
                      "Blocage sans risque, la recherche locale continue.", "gourmand"),
    "searchhost.exe": ("Recherche Windows / Bing",
                       "Recherche en ligne depuis le menu Demarrer.",
                       "Blocage sans risque.", "gourmand"),
    "startmenuexperiencehost.exe": ("Menu Demarrer",
                                    "Affiche le menu Demarrer et ses suggestions en ligne.",
                                    "Blocage sans risque.", "gourmand"),
    "widgets.exe": ("Widgets Windows 11",
                    "Le panneau meteo et actualites en bas a gauche.",
                    "Gros consommateur d'images. Blocage sans risque.", "gourmand"),
    "widgetservice.exe": ("Service des widgets Windows 11",
                          "Alimente le panneau meteo et actualites.",
                          "Blocage sans risque.", "gourmand"),
    "runtimebroker.exe": ("Intermediaire des applications du Microsoft Store",
                          "Gere les permissions des applications du Store.",
                          "Depend de l'application qui l'a lance.", "utile"),
    "backgroundtaskhost.exe": ("Taches de fond d'applications du Store",
                               "Execute les mises a jour discretes des applications "
                               "du Store.", "Souvent superflu.", "gourmand"),
    "wsappx": ("Store Windows", "Installe et met a jour les applications du Store.",
               "A bloquer si l'enveloppe est serree.", "gourmand"),
    "winstore.app.exe": ("Microsoft Store",
                         "La boutique d'applications de Windows.",
                         "Tres gourmand lors des mises a jour.", "gourmand"),
    "onedrive.exe": ("OneDrive (cloud Microsoft)",
                     "Synchronise tes dossiers avec le cloud Microsoft.",
                     "Peut avaler toute l'enveloppe d'un coup.", "gourmand"),
    "dropbox.exe": ("Dropbox (cloud)", "Synchronise des fichiers avec Dropbox.",
                    "Peut avaler toute l'enveloppe d'un coup.", "gourmand"),
    "googledrivefs.exe": ("Google Drive (cloud)",
                          "Synchronise des fichiers avec Google Drive.",
                          "Peut avaler toute l'enveloppe d'un coup.", "gourmand"),
    "msedge.exe": ("Navigateur Microsoft Edge", "Le navigateur web de Microsoft.",
                   "Consommation selon ton usage.", "utile"),
    "msedgewebview2.exe": ("Moteur Edge embarque",
                           "Affiche des pages web a l'interieur d'autres logiciels "
                           "(Office, Teams, widgets).",
                           "Souvent de la publicite ou du contenu en ligne non demande.",
                           "gourmand"),
    "chrome.exe": ("Navigateur Google Chrome", "Le navigateur web de Google.",
                   "Consommation selon ton usage.", "utile"),
    "firefox.exe": ("Navigateur Mozilla Firefox", "Le navigateur web de Mozilla.",
                    "Consommation selon ton usage.", "utile"),
    "teams.exe": ("Microsoft Teams", "Messagerie et visio d'equipe.",
                  "La visio est tres gourmande.", "gourmand"),
    "ms-teams.exe": ("Microsoft Teams", "Messagerie et visio d'equipe.",
                     "La visio est tres gourmande.", "gourmand"),
    "zoom.exe": ("Zoom", "Visioconference.",
                 "Environ 500 Mo par heure de video.", "gourmand"),
    "outlook.exe": ("Microsoft Outlook", "Courrier electronique et agenda.",
                    "Raisonnable, sauf grosses pieces jointes.", "utile"),
    "thunderbird.exe": ("Mozilla Thunderbird", "Courrier electronique.",
                        "Raisonnable.", "utile"),
    "spotify.exe": ("Spotify", "Musique en ligne.",
                    "Environ 60 a 150 Mo par heure.", "gourmand"),
    "steam.exe": ("Steam (jeux)", "Boutique et mises a jour de jeux.",
                  "Mises a jour de plusieurs Go. A bloquer.", "gourmand"),
    "epicgameslauncher.exe": ("Epic Games", "Boutique et mises a jour de jeux.",
                              "Mises a jour de plusieurs Go. A bloquer.", "gourmand"),
    "discord.exe": ("Discord", "Messagerie vocale et texte.",
                    "Modere, sauf appels video.", "utile"),
    "adobearmsvc.exe": ("Mise a jour Adobe", "Cherche des mises a jour Adobe.",
                        "Blocage sans risque.", "gourmand"),
    "acrobat.exe": ("Adobe Acrobat", "Lecteur et editeur de PDF.",
                    "Consommation faible.", "utile"),
    "dllhost.exe": ("Hote de composants Windows",
                    "Execute un composant pour le compte d'un autre programme.",
                    "Depend du programme appelant.", "utile"),
    "taskhostw.exe": ("Hote de taches planifiees Windows",
                      "Execute les taches programmees du systeme.",
                      "Souvent des mises a jour ou de la telemetrie.", "utile"),
    "smartscreen.exe": ("SmartScreen (securite Windows)",
                        "Verifie en ligne la reputation des fichiers telecharges.",
                        "Trafic tres faible, utile.", "utile"),
    "msmpeng.exe": ("Antivirus Windows Defender",
                    "Analyse les fichiers et telecharge ses signatures.",
                    "Quelques Mo par jour, a laisser passer.", "utile"),
    "securityhealthservice.exe": ("Securite Windows",
                                  "Etat de la protection du PC.",
                                  "Trafic negligeable.", "utile"),
    "python.exe": ("Python", "Un script Python (peut-etre NetGate lui-meme).",
                   "Depend du script.", "utile"),
    "pythonw.exe": ("Python (sans fenetre)", "Un script Python en arriere-plan.",
                    "Depend du script.", "utile"),
}

# Reconnaissance par mot-cle quand le nom exact est inconnu
KEYWORD_HINTS = [
    (("update", "updater", "upd", "maj"), "Mise a jour automatique",
     "Ce programme telecharge des mises a jour d'un logiciel.",
     "Souvent tres gourmand. A bloquer si l'enveloppe est serree.", "gourmand"),
    (("crash", "report", "telemetry", "telemetrie", "diagnostic"),
     "Rapport d'erreur ou telemetrie",
     "Envoie des donnees de diagnostic a l'editeur du logiciel.",
     "Aucun interet pour toi. Blocage sans risque.", "gourmand"),
    (("sync", "cloud", "backup", "sauvegarde"), "Synchronisation / sauvegarde",
     "Envoie ou recupere des fichiers sur un serveur distant.",
     "Peut consommer enormement sans prevenir.", "gourmand"),
    (("setup", "install"), "Programme d'installation",
     "Installe ou telecharge un logiciel.",
     "Telechargement potentiellement lourd.", "gourmand"),
    (("host", "service", "svc", "agent", "daemon"), "Service en arriere-plan",
     "Composant qui tourne sans fenetre, lance par un autre logiciel.",
     "Verifie le dossier d'origine avant d'autoriser.", "utile"),
]

PORT_HINTS = {
    80: "site web (non securise)", 443: "site web securise", 53: "annuaire des noms (DNS)",
    21: "transfert de fichiers FTP", 22: "connexion securisee SSH",
    25: "envoi de courrier", 110: "releve de courrier", 143: "releve de courrier IMAP",
    465: "envoi de courrier securise", 587: "envoi de courrier", 993: "courrier IMAP securise",
    995: "courrier POP securise", 3389: "bureau a distance", 123: "mise a l'heure",
    1935: "flux video", 3478: "appel audio/video", 5060: "telephonie",
}


def file_version_info(path):
    """Lit la fiche d'identite du fichier .exe (comme la colonne Description
    de l'Explorateur Windows)."""
    out = {}
    try:
        ver = ctypes.windll.version
        ver.GetFileVersionInfoSizeW.restype = ctypes.c_uint
        size = ver.GetFileVersionInfoSizeW(ctypes.c_wchar_p(path), None)
        if not size:
            return out
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(ctypes.c_wchar_p(path), 0, size, buf):
            return out
        ptr = ctypes.c_void_p()
        ln = ctypes.c_uint()
        if not ver.VerQueryValueW(buf, ctypes.c_wchar_p("\\VarFileInfo\\Translation"),
                                  ctypes.byref(ptr), ctypes.byref(ln)) or not ln.value:
            return out
        arr = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ushort))
        lang, cp = arr[0], arr[1]
        for key in ("FileDescription", "CompanyName", "ProductName", "FileVersion"):
            sub = "\\StringFileInfo\\%04x%04x\\%s" % (lang, cp, key)
            p2 = ctypes.c_void_p()
            n2 = ctypes.c_uint()
            if ver.VerQueryValueW(buf, ctypes.c_wchar_p(sub), ctypes.byref(p2),
                                  ctypes.byref(n2)) and n2.value:
                val = ctypes.wstring_at(p2, n2.value - 1).strip()
                if val:
                    out[key] = val
    except Exception:
        pass
    return out


def window_titles(pid):
    """Titres des fenetres visibles du processus : souvent le plus parlant."""
    titles = []
    try:
        user32 = ctypes.windll.user32
        proto = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def cb(hwnd, _lp):
            pid_buf = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_buf))
            if pid_buf.value == pid and user32.IsWindowVisible(hwnd):
                n = user32.GetWindowTextLengthW(hwnd)
                if n:
                    b = ctypes.create_unicode_buffer(n + 1)
                    user32.GetWindowTextW(hwnd, b, n + 1)
                    t = b.value.strip()
                    if t and t not in titles:
                        titles.append(t)
            return True

        user32.EnumWindows(proto(cb), 0)
    except Exception:
        pass
    return titles[:3]


def svchost_services(pid):
    """Quel service Windows se cache derriere ce svchost."""
    try:
        p = subprocess.run(["tasklist", "/svc", "/FI", "PID eq %d" % pid,
                            "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, timeout=6,
                           creationflags=CREATE_NO_WINDOW, errors="ignore")
        line = (p.stdout or "").strip().splitlines()
        if not line:
            return []
        parts = re.findall(r'"([^"]*)"', line[0])
        if len(parts) >= 3:
            return [s.strip() for s in parts[2].split(",") if s.strip()
                    and s.strip().upper() != "N/A"]
    except Exception:
        pass
    return []


SERVICE_NAMES = {
    "dosvc": "Optimisation de distribution (telechargement des mises a jour) - TRES gourmand",
    "wuauserv": "Windows Update - TRES gourmand",
    "bits": "Transfert en arriere-plan (mises a jour) - gourmand",
    "dnscache": "Annuaire des noms de sites (DNS) - indispensable",
    "dhcp": "Attribution d'adresse reseau - indispensable",
    "nlasvc": "Detection du type de reseau - indispensable",
    "wlansvc": "Wi-Fi - indispensable",
    "cryptsvc": "Verification des certificats - utile",
    "netprofm": "Profils reseau - indispensable",
    "iphlpsvc": "Assistance IP - utile",
    "lanmanworkstation": "Partage de fichiers Windows",
    "timebrokersvc": "Taches planifiees d'applications",
    "usosvc": "Orchestrateur de mises a jour - gourmand",
    "wsearch": "Recherche Windows",
    "diagtrack": "Telemetrie Microsoft - blocage sans risque",
    "webthreatdefsvc": "Protection navigation (Defender)",
    "wscsvc": "Centre de securite Windows",
}


def path_category(path):
    p = (path or "").lower()
    win = (os.environ.get("SystemRoot", r"C:\Windows")).lower()
    if p.startswith(win):
        return ("Composant de Windows", C_ACCENT)
    if "\\program files" in p:
        return ("Logiciel installe normalement", C_OK)
    if "\\appdata\\local\\temp" in p or "\\windows\\temp" in p:
        return ("Fichier temporaire - origine douteuse", C_DANGER)
    if "\\appdata\\" in p:
        return ("Installe dans ton profil utilisateur", C_WARN)
    if "\\users\\" in p and ("\\downloads" in p or "\\telechargements" in p):
        return ("Lance depuis les telechargements - prudence", C_DANGER)
    return ("Emplacement inhabituel", C_WARN)


class Inspector:
    """Traduit un processus en informations comprehensibles."""

    _ver_cache = {}
    _sig_cache = {}
    _dns_cache = {}

    @classmethod
    def fast(cls, path, pid):
        """Infos immediates (quelques millisecondes)."""
        base = os.path.basename(path or "").lower()
        info = {"path": path, "pid": pid, "base": base}

        vi = cls._ver_cache.get(path.lower())
        if vi is None:
            vi = file_version_info(path) if path and os.path.isfile(path) else {}
            cls._ver_cache[path.lower()] = vi
        info["description"] = vi.get("FileDescription") or ""
        info["editeur"] = vi.get("CompanyName") or ""
        info["produit"] = vi.get("ProductName") or ""
        info["version"] = vi.get("FileVersion") or ""

        g = GLOSSARY.get(base)
        if g:
            info["titre"], info["quoi"], info["conseil"], info["niveau"] = g
        else:
            info["titre"] = info["description"] or info["produit"] or base
            info["quoi"] = ""
            info["conseil"] = ""
            info["niveau"] = "utile"
            for keys, titre, quoi, conseil, niveau in KEYWORD_HINTS:
                if any(k in base for k in keys):
                    info["quoi"] = quoi
                    info["conseil"] = conseil
                    info["niveau"] = niveau
                    if not info["description"]:
                        info["titre"] = titre
                    break
            if not info["quoi"]:
                if info["editeur"]:
                    info["quoi"] = "Logiciel edite par %s." % info["editeur"]
                else:
                    info["quoi"] = ("Programme non identifie : aucune fiche d'identite "
                                    "dans le fichier. Prudence.")
                    info["niveau"] = "inconnu"

        info["origine"], info["origine_couleur"] = path_category(path)
        info["fenetres"] = window_titles(pid) if pid else []

        parent = ""
        if psutil and pid:
            try:
                parent = psutil.Process(pid).parent().name()
            except Exception:
                parent = ""
        info["parent"] = parent
        return info

    @classmethod
    def slow(cls, info):
        """Infos plus lentes : signature, services, destinations. A executer
        dans un thread."""
        path, pid = info.get("path"), info.get("pid")
        out = {}

        # Signature numerique = qui garantit ce fichier
        key = (path or "").lower()
        if key in cls._sig_cache:
            out["signature"] = cls._sig_cache[key]
        elif path:
            sig = ""
            try:
                cmd = ("$s=Get-AuthenticodeSignature -LiteralPath '%s';"
                       "if($s.Status -eq 'Valid'){$s.SignerCertificate.Subject}"
                       "else{'NON SIGNE'}" % path.replace("'", "''"))
                p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                                    "-Command", cmd],
                                   capture_output=True, text=True, timeout=12,
                                   creationflags=CREATE_NO_WINDOW, errors="ignore")
                raw = (p.stdout or "").strip()
                if raw == "NON SIGNE":
                    sig = "non signe numeriquement - prudence"
                else:
                    m = re.search(r"CN=([^,]+)", raw)
                    sig = ("signe par %s" % m.group(1).strip()) if m else raw[:80]
            except Exception:
                sig = ""
            cls._sig_cache[key] = sig
            out["signature"] = sig

        # Service porte par svchost
        if info.get("base") == "svchost.exe" and pid:
            svcs = svchost_services(pid)
            lisibles = []
            for s in svcs:
                lisibles.append("%s (%s)" % (s, SERVICE_NAMES[s.lower()])
                                if s.lower() in SERVICE_NAMES else s)
            out["services"] = lisibles

        # Destinations contactees
        dests = []
        if psutil and pid:
            try:
                for c in proc_connections(psutil.Process(pid), kind="inet"):
                    if not c.raddr:
                        continue
                    ip, port = c.raddr[0], c.raddr[1]
                    if ip in ("127.0.0.1", "::1"):
                        continue
                    host = cls._dns_cache.get(ip)
                    if host is None:
                        try:
                            socket.setdefaulttimeout(1.5)
                            host = socket.gethostbyaddr(ip)[0]
                        except Exception:
                            host = ""
                        cls._dns_cache[ip] = host
                    label = host or ip
                    usage = PORT_HINTS.get(port, "port %d" % port)
                    entry = "%s  -  %s" % (label, usage)
                    if entry not in dests:
                        dests.append(entry)
                    if len(dests) >= 4:
                        break
            except Exception:
                pass
        out["destinations"] = dests
        return out


# ==========================================================================
#  NOTIFICATION D'AUTORISATION (coin bas-droit)
# ==========================================================================

NIVEAU_STYLE = {
    "systeme":  (C_ACCENT, "Composant du systeme"),
    "utile":    (C_OK, "Programme identifie"),
    "gourmand": (C_WARN, "Gros consommateur potentiel"),
    "inconnu":  (C_DANGER, "Programme non identifie"),
}


class AuthToast(tk.Toplevel):
    W = 470

    def __init__(self, master, item, color, timeout, on_decision, lifetime=0):
        super().__init__(master)
        self.on_decision = on_decision
        self.item = item
        self.remaining = timeout
        self._done = False
        self.expanded = False

        self.info = Inspector.fast(item["path"], item.get("pid"))

        self.overrideredirect(True)
        self.attributes("-topmost", True)
        try:
            self.attributes("-alpha", 0.98)
        except Exception:
            pass
        self.configure(bg=C_LINE)

        body = tk.Frame(self, bg=C_PANEL)
        body.pack(fill="both", expand=True, padx=1, pady=1)
        tk.Frame(body, bg=color, height=4).pack(fill="x")

        pad = 20
        tk.Label(body, text="Demande d'acces Internet", bg=C_PANEL, fg=C_TXT_DIM,
                 font=("Segoe UI", 9)).pack(anchor="w", padx=pad, pady=(12, 0))

        # Titre le plus parlant possible
        titre = self.info["titre"] or os.path.basename(item["path"])
        tk.Label(body, text=titre, bg=C_PANEL, fg=C_TXT, wraplength=self.W - 2 * pad,
                 justify="left", font=("Segoe UI Semibold", 14)).pack(anchor="w", padx=pad)

        sous = os.path.basename(item["path"])
        if self.info["editeur"]:
            sous += "   -   " + self.info["editeur"]
        tk.Label(body, text=sous, bg=C_PANEL, fg=C_TXT_DIM, wraplength=self.W - 2 * pad,
                 justify="left", font=("Segoe UI", 9)).pack(anchor="w", padx=pad, pady=(1, 0))

        # Etiquette de niveau
        col, lab = NIVEAU_STYLE.get(self.info["niveau"], NIVEAU_STYLE["utile"])
        tag = tk.Frame(body, bg=C_PANEL)
        tag.pack(anchor="w", padx=pad, pady=(8, 0))
        tk.Label(tag, text="  %s  " % lab, bg=col, fg="#10141a",
                 font=("Segoe UI Semibold", 8)).pack(side="left")
        tk.Label(tag, text="  " + self.info["origine"], bg=C_PANEL,
                 fg=self.info["origine_couleur"],
                 font=("Segoe UI", 8)).pack(side="left")

        # A quoi ca sert
        tk.Label(body, text=self.info["quoi"], bg=C_PANEL, fg=C_TXT,
                 wraplength=self.W - 2 * pad, justify="left",
                 font=("Segoe UI", 9)).pack(anchor="w", padx=pad, pady=(10, 0))

        if self.info["conseil"]:
            tk.Label(body, text="Conseil : " + self.info["conseil"], bg=C_PANEL,
                     fg=col, wraplength=self.W - 2 * pad, justify="left",
                     font=("Segoe UI Semibold", 9)).pack(anchor="w", padx=pad, pady=(6, 0))

        # Lignes enrichies en arriere-plan
        self.lbl_live = tk.Label(body, text="Analyse en cours...", bg=C_PANEL,
                                 fg=C_TXT_DIM, wraplength=self.W - 2 * pad,
                                 justify="left", font=("Segoe UI", 8))
        self.lbl_live.pack(anchor="w", padx=pad, pady=(10, 0))

        if lifetime:
            tk.Label(body, text="Deja consomme par ce programme : %s" % fmt_bytes(lifetime),
                     bg=C_PANEL, fg=C_TXT_DIM,
                     font=("Segoe UI", 8)).pack(anchor="w", padx=pad, pady=(4, 0))

        # Volet details repliable
        self.details = tk.Label(body, text="", bg=C_PANEL2, fg=C_TXT_DIM,
                                wraplength=self.W - 2 * pad - 16, justify="left",
                                font=("Consolas", 8), anchor="w", padx=8, pady=8)

        self.lbl_cd = tk.Label(body, text="", bg=C_PANEL, fg=C_TXT_DIM,
                               font=("Segoe UI", 8))
        self.lbl_cd.pack(anchor="w", padx=pad, pady=(8, 0))

        bar = tk.Frame(body, bg=C_PANEL)
        bar.pack(side="bottom", fill="x", padx=pad, pady=14)
        self._mkbtn(bar, "Autoriser", C_OK, "#06251a",
                    lambda: self._decide(True)).pack(side="left")
        self._mkbtn(bar, "Bloquer", C_DANGER, "#2a0808",
                    lambda: self._decide(False)).pack(side="left", padx=8)
        self.btn_det = self._mkbtn(bar, "Details", C_PANEL2, C_TXT, self._toggle_details)
        self.btn_det.pack(side="left")
        self._mkbtn(bar, "Plus tard", C_PANEL2, C_TXT,
                    lambda: self._decide(None)).pack(side="right")

        self._place(self._needed_height())
        self._countdown()
        threading.Thread(target=self._enrich, daemon=True).start()

    # ------------------------------------------------------------------
    def _needed_height(self):
        self.update_idletasks()
        return max(300, self.winfo_reqheight())

    def _place(self, h):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry("%dx%d+%d+%d" % (self.W, h, sw - self.W - 18, sh - h - 70))

    @staticmethod
    def _mkbtn(parent, text, bg, fg, cmd):
        return tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg,
                         activebackground=bg, activeforeground=fg, relief="flat",
                         bd=0, font=("Segoe UI Semibold", 9), padx=14, pady=7,
                         cursor="hand2", highlightthickness=0)

    def _detail_text(self):
        i = self.info
        lines = ["Fichier    : %s" % i["path"],
                 "Numero PID : %s" % i.get("pid", "?")]
        if i.get("version"):
            lines.append("Version    : %s" % i["version"])
        if i.get("produit"):
            lines.append("Produit    : %s" % i["produit"])
        if i.get("parent"):
            lines.append("Lance par  : %s" % i["parent"])
        if i.get("fenetres"):
            lines.append("Fenetre    : %s" % " | ".join(i["fenetres"]))
        if i.get("services"):
            lines.append("Services   :")
            lines += ["   - " + s for s in i["services"]]
        if i.get("signature"):
            lines.append("Signature  : %s" % i["signature"])
        if i.get("destinations"):
            lines.append("Contacte   :")
            lines += ["   - " + d for d in i["destinations"]]
        return "\n".join(lines)

    def _toggle_details(self):
        if self._done:
            return
        self.expanded = not self.expanded
        if self.expanded:
            self.details.configure(text=self._detail_text())
            self.details.pack(fill="x", padx=20, pady=(10, 0), before=self.lbl_cd)
            self.btn_det.configure(text="Masquer")
        else:
            self.details.pack_forget()
            self.btn_det.configure(text="Details")
        self._place(self._needed_height())

    def _enrich(self):
        try:
            extra = Inspector.slow(self.info)
        except Exception:
            extra = {}
        self.after(0, lambda: self._apply_enrich(extra))

    def _apply_enrich(self, extra):
        if self._done:
            return
        self.info.update(extra)
        bits = []
        if extra.get("services"):
            bits.append("Service Windows : " + extra["services"][0])
        if extra.get("destinations"):
            bits.append("Contacte : " + extra["destinations"][0])
        if extra.get("signature"):
            bits.append("Editeur verifie : " + extra["signature"]
                        if "signe par" in extra["signature"] else extra["signature"])
        self.lbl_live.configure(
            text="\n".join(bits) if bits else "Aucune destination identifiee pour l'instant.",
            fg=C_DANGER if "non signe" in (extra.get("signature") or "") else C_TXT_DIM)
        if self.expanded:
            self.details.configure(text=self._detail_text())
        self._place(self._needed_height())

    def _countdown(self):
        if self._done:
            return
        if self.remaining <= 0:
            self._decide(None)
            return
        self.lbl_cd.configure(text="Sans reponse, la demande ira dans la liste "
                                   "d'attente (%d s)" % self.remaining)
        self.remaining -= 1
        self.after(1000, self._countdown)

    def _decide(self, value):
        if self._done:
            return
        self._done = True
        try:
            self.destroy()
        except Exception:
            pass
        self.on_decision(self.item, value)


# ==========================================================================
#  ICONE : blason dont le remplissage suit la consommation
# ==========================================================================

def _shield_points(size, inset=0.0):
    """Contour d'un blason : haut plat, flancs droits puis incurves vers une
    pointe basse. inset retrecit la forme vers son centre."""
    w = float(size)

    def bez(p0, p1, p2, n=14):
        pts = []
        for i in range(1, n + 1):
            t = i / float(n)
            u = 1 - t
            pts.append((u * u * p0[0] + 2 * u * t * p1[0] + t * t * p2[0],
                        u * u * p0[1] + 2 * u * t * p1[1] + t * t * p2[1]))
        return pts

    pts = [(0.10, 0.09), (0.90, 0.09), (0.90, 0.45)]
    pts += bez((0.90, 0.45), (0.885, 0.80), (0.50, 0.96))
    pts += bez((0.50, 0.96), (0.115, 0.80), (0.10, 0.45))
    pts.append((0.10, 0.09))

    cx, cy = 0.50, 0.52
    k = 1.0 - inset
    return [((cx + (x - cx) * k) * w, (cy + (y - cy) * k) * w) for x, y in pts]


def build_icon_image(color, pct, size=256):
    """Blason : contour a la couleur du profil, interieur rempli de bas en haut
    selon la part d'enveloppe consommee (vert -> orange -> rouge)."""
    if Image is None:
        return None
    ss = size * 4  # dessin en grand puis reduction : bords lisses
    img = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))

    def mask_of(inset):
        m = Image.new("L", (ss, ss), 0)
        ImageDraw.Draw(m).polygon(_shield_points(ss, inset), fill=255)
        return m

    m_out, m_gap, m_in = mask_of(0.0), mask_of(0.10), mask_of(0.15)

    # 1. contour plein a la couleur du profil
    img.paste(Image.new("RGBA", (ss, ss), color), (0, 0), m_out)
    # 2. liseré sombre : empeche la jauge de se confondre avec le contour
    img.paste(Image.new("RGBA", (ss, ss), (16, 20, 26, 255)), (0, 0), m_gap)
    # 3. fond interieur
    img.paste(Image.new("RGBA", (ss, ss), (32, 36, 44, 255)), (0, 0), m_in)

    # 4. jauge de consommation, de bas en haut
    pct = max(0.0, min(1.0, pct))
    if pct > 0.01:
        gauge = C_OK if pct < 0.5 else (C_WARN if pct < 0.9 else C_DANGER)
        top_y = ss * (0.90 - 0.78 * pct)
        layer = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
        ImageDraw.Draw(layer).rectangle((0, top_y, ss, ss), fill=gauge)
        img.paste(layer, (0, 0), m_in)

    # 5. barriere : le "portail" ferme
    d = ImageDraw.Draw(img)
    d.rectangle((ss * 0.26, ss * 0.415, ss * 0.74, ss * 0.505), fill=(16, 20, 26, 255))

    return img.resize((size, size), Image.LANCZOS)


def write_ico(color, pct):
    """Ecrit un .ico multi-tailles et renvoie son chemin (icone de fenetre et
    de barre des taches)."""
    img = build_icon_image(color, pct, 256)
    if img is None:
        return None
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        img.save(ICO_PATH, format="ICO",
                 sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64),
                        (128, 128), (256, 256)])
        return ICO_PATH
    except Exception:
        return None


# ==========================================================================
#  ICONE ZONE DE NOTIFICATION
# ==========================================================================

class Tray:
    def __init__(self, app):
        self.app = app
        self.icon = None
        self.available = pystray is not None and Image is not None

    def _image(self, color, pct):
        return build_icon_image(color, pct, 64)

    def _menu(self):
        sm = self.app.state_mgr
        items = [pystray.MenuItem("Ouvrir NetGate", self._open, default=True)]
        if sm.multi_profiles():
            subs = []
            for pid in sm.profile_ids():
                subs.append(pystray.MenuItem(
                    sm.data["profiles"][pid]["name"],
                    (lambda p: (lambda icon, item: self._switch(p)))(pid),
                    checked=(lambda p: (lambda item: sm.data["active_profile"] == p))(pid),
                    radio=True))
            items.append(pystray.MenuItem("Profil", pystray.Menu(*subs)))
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem(self._usage_text, None, enabled=False))
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Tout debloquer (PANIQUE)", self._panic))
        items.append(pystray.MenuItem("Quitter", self._quit))
        return pystray.Menu(*items)

    def _usage_text(self, item=None):
        sm = self.app.state_mgr
        return "%s / %d Mo  -  %s" % (fmt_bytes(sm.total_used()),
                                      sm.data["quota_mb"], sm.profile_name())

    def _open(self, icon=None, item=None):
        self.app.after(0, self.app.show_window)

    def _switch(self, pid):
        self.app.after(0, lambda: self.app.set_profile(pid))

    def _panic(self, icon=None, item=None):
        self.app.after(0, self.app.panic)

    def _quit(self, icon=None, item=None):
        self.app.after(0, self.app.quit_app)

    def start(self):
        if not self.available:
            return
        sm = self.app.state_mgr
        pct = sm.total_used() / float(sm.quota_bytes())
        self.icon = pystray.Icon(APP_NAME, self._image(sm.profile_color(), pct),
                                 "%s %s - %s" % (APP_NAME, VERSION_TXT, sm.profile_name()),
                                 self._menu())
        threading.Thread(target=self.icon.run, daemon=True, name="Tray").start()

    def refresh(self):
        if not self.icon:
            return
        sm = self.app.state_mgr
        pct = sm.total_used() / float(sm.quota_bytes())
        try:
            self.icon.icon = self._image(sm.profile_color(), pct)
            self.icon.title = "%s %s - %s - %s / %d Mo" % (
                APP_NAME, VERSION_TXT, sm.profile_name(), fmt_bytes(sm.total_used()),
                sm.data["quota_mb"])
            self.icon.update_menu()
        except Exception:
            pass

    def notify(self, title, msg):
        if not self.icon:
            return
        try:
            self.icon.notify(msg, title)
        except Exception:
            pass

    def stop(self):
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass


# ==========================================================================
#  AIDE INTEGREE (touche F1)
# ==========================================================================

HELP = [
    ("h1", "NetGate en trois phrases"),
    ("p", "NetGate ferme le robinet Internet pour tout le monde, puis tu l'ouvres "
          "programme par programme. Il compte ce que chacun consomme et te previent "
          "quand ton enveloppe du jour s'epuise. Rien n'est jamais coupe sans que tu "
          "l'aies decide."),

    ("h1", "Le bouton \"Activer la protection\""),
    ("p", "C'est l'interrupteur general."),
    ("h2", "Protection inactive"),
    ("p", "NetGate ne bloque rien. Il regarde, il compte, il te pose des questions et "
          "il retient tes reponses, mais tout le monde sort librement. C'est le mode a "
          "utiliser les premieres heures pour decouvrir qui consomme quoi sans rien "
          "casser."),
    ("h2", "Protection active"),
    ("p", "NetGate donne trois ordres au pare-feu de Windows : le trafic sortant est "
          "refuse par defaut sur les trois profils reseau ; une autorisation est creee "
          "pour chaque programme de ta liste ; la regle DNS/DHCP est posee si tu l'as "
          "cochee. Ce qui n'est pas dans ta liste ne sort plus."),
    ("warn", "Ces regles vivent dans Windows, pas dans NetGate. En quittant "
             "normalement, NetGate les supprime toutes et Internet redevient normal. "
             "Si le programme est tue brutalement, le blocage reste en place : "
             "relance NetGate, ou utilise le bouton PANIQUE."),

    ("h1", "Premier demarrage, dans l'ordre"),
    ("p", "1. Reglages : enveloppe du jour, heure de remise a zero, case DNS/DHCP.\n"
          "2. Activer la protection.\n"
          "3. Ouvre ton navigateur : une notification apparait, clique Autoriser.\n"
          "4. Repete pour chaque programme dont tu as besoin. Au bout de dix minutes "
          "tu n'es plus derange."),

    ("h1", "Les notifications"),
    ("p", "Des qu'un programme essaie de sortir, une carte apparait en bas a droite "
          "avec son nom lisible, son editeur, ce a quoi il sert et un conseil. Trois "
          "reponses : Autoriser, Bloquer, ou Plus tard, qui met la demande en attente "
          "sans rien decider. Le bouton Details montre le chemin du fichier, la "
          "signature numerique, le site contacte et, pour svchost, le service exact "
          "qui se cache derriere."),

    ("h1", "La liste des applications"),
    ("p", "Vert autorise, rouge bloque, orange en attente. Clique sur un en-tete de "
          "colonne pour trier par acces ou par volume consomme, une seconde fois pour "
          "inverser l'ordre. Double-clic sur une ligne "
          "pour changer d'avis. La fiche du bas explique de quoi il s'agit. Le bouton "
          "Ajouter un programme sert a autoriser quelque chose a l'avance, sans "
          "attendre qu'il se manifeste."),

    ("h1", "L'enveloppe et sa remise a zero"),
    ("p", "L'enveloppe n'est decomptee que lorsque la protection est active. "
          "Protection inactive, NetGate continue de mesurer et d'attribuer le "
          "trafic a chaque programme, mais il l'affiche a part : ton quota du jour "
          "n'est pas entame par une periode d'observation.\n\n"
          "La remise a zero se fait a l'heure choisie, meme si le PC etait eteint : "
          "au demarrage NetGate compare la date de la derniere periode enregistree "
          "a la date du jour, et bascule si l'heure de remise a zero est passee.\n\n"
          "Reglages propose aussi un bouton \"Remettre le compteur a zero\" qui fait repartir "
          "la consommation de 0 "
          "sans toucher a tes autorisations : utile apres un rechargement de forfait ou "
          "un changement de reseau.\n\n"
          "Le quota est une reference, pas une barriere : a 50, 80 et 100 pour cent, "
          "NetGate previent, mais ne coupe rien. L'heure de remise a zero se regle a "
          "la minute pres, sur l'heure de ton PC ou sur l'heure UTC selon ce "
          "qu'impose ton fournisseur d'acces."),

    ("h1", "Les plages horaires"),
    ("p", "Reglages, bouton \"Plages horaires\" : un tableau des 48 demi-heures de la "
          "journee. Coche celles pendant lesquelles Internet est autorise. En dehors, "
          "plus rien ne sort, meme les programmes de ta liste. Les memes horaires "
          "s'appliquent tous les jours ; des raccourcis permettent de tout ouvrir, "
          "tout fermer, ou selectionner 08h-22h d'un clic. Le bandeau indique la "
          "prochaine ouverture ou fermeture."),

    ("h1", "L'icone pres de l'horloge"),
    ("p", "La croix ferme la fenetre mais NetGate continue de surveiller ; le blocage "
          "reste actif. Pour tout arreter, utilise Quitter dans le menu de l'icone : "
          "les regles sont alors supprimees automatiquement. Clic droit sur l'icone "
          "pour rouvrir, voir les Mo restants, tout debloquer ou quitter. "
          "Le blason se remplit avec ta consommation : vert, puis orange, puis rouge."),

    ("h1", "Les profils, facultatifs"),
    ("p", "Par defaut il n'y a qu'une seule liste d'autorisations et c'est tres bien "
          "ainsi. Si tu veux basculer d'un usage a l'autre (travail, visio, blackout), "
          "cree des profils dans Reglages : une barre de choix apparaitra alors en "
          "haut de la fenetre."),

    ("h1", "Effacer et recommencer"),
    ("p", "Reglages propose de reinitialiser les choix de la liste active, ou "
          "d'effacer plus largement : compteurs du jour, historique, autorisations, "
          "ou tout remettre a neuf. Les regles du pare-feu sont nettoyees avant, pour "
          "qu'aucun programme ne reste bloque sans moyen de le debloquer."),

    ("h1", "Ou sont mes donnees"),
    ("code", "@DOSSIER@"),
    ("p", "Les fichiers sont ranges a cote de netgate.py. netgate.state.json "
          "contient tout : reglages, autorisations, compteurs, historique. "
          "Copie-le ailleurs pour sauvegarder ta configuration. netgate.log recoit les "
          "erreurs eventuelles. Les regles creees dans le pare-feu Windows portent "
          "toutes le prefixe NETGATE_."),

    ("h1", "A propos"),
    ("about", ""),

    ("h1", "Si quelque chose ne va pas"),
    ("p", "Plus rien ne se connecte, meme les programmes autorises : la case DNS/DHCP "
          "n'est pas cochee.\n"
          "NetGate ne demarre pas : ouvre Terminal (administrateur) et lance-le de la "
          "pour voir l'erreur, ou consulte netgate.log.\n"
          "Le comptage indique \"global estime\" au lieu du detail : le module "
          "pywintrace n'est pas installe.\n"
          "En cas de doute, PANIQUE retablit Internet immediatement."),
]


# ==========================================================================
#  FENETRE PRINCIPALE
# ==========================================================================

class NetGateApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.state_mgr = State()
        self.pending_q = queue.Queue()
        self.pending = []
        self.toast = None
        self.profile_cards = {}
        self.help_win = None
        self.applied = set()      # regles reellement posees dans le pare-feu
        self._fw_lock = threading.Lock()
        self._fw_busy = False
        self._fw_pending = False
        self._fw_full = False
        self._slot_state = None   # etat de la plage horaire au dernier passage
        self.sort_key = "acces"   # colonne de tri de la liste principale
        self.sort_desc = False
        self.rates = {}          # chemin -> octets/seconde (instantane)
        self._last_tick = time.time()

        self.meter = EtwMeter()
        self.scanner = ConnScanner(self.state_mgr.decided_paths, self.pending_q)
        self.tray = Tray(self)

        self.title("%s %s  -  mon enveloppe Internet" % (APP_NAME, VERSION_TXT))
        self.geometry("1060x780")
        self.minsize(940, 700)
        self.configure(bg=C_BG)
        self.protocol("WM_DELETE_WINDOW", self.hide_window)

        self._style()
        self._build()
        self.bind_all("<F1>", self.show_help)
        self._icon_sig = None
        self.refresh_window_icon()

        self._roll_au_demarrage = self.state_mgr.roll_period_if_needed()
        self.meter.start()
        self.scanner.start()
        self.tray.start()

        self.after(400, self._loop_fast)
        self.after(900, self._loop_slow)
        self.after(700, self._startup_checks)

        if self.state_mgr.data.get("start_minimized"):
            self.after(1200, self.hide_window)

    # ------------------------------------------------------------ apparence
    def _style(self):
        try:
            self._style_inner()
        except Exception:
            log_line("Theme non applique :\n" + traceback.format_exc())

    def _style_inner(self):
        # Les listes deroulantes de Tk ne suivent PAS le theme ttk : elles se
        # configurent via la base d'options, sinon elles restent blanches.
        self.option_add("*TCombobox*Listbox.background", C_PANEL2)
        self.option_add("*TCombobox*Listbox.foreground", C_TXT)
        self.option_add("*TCombobox*Listbox.selectBackground", C_ACCENT)
        self.option_add("*TCombobox*Listbox.selectForeground", "#06101d")
        self.option_add("*TCombobox*Listbox.font", ("Segoe UI", 10))
        self.option_add("*TCombobox*Listbox.borderWidth", 0)
        self.option_add("*TCombobox*Listbox.highlightThickness", 0)
        self.option_add("*Listbox.background", C_PANEL2)
        self.option_add("*Listbox.foreground", C_TXT)
        self.option_add("*Menu.background", C_PANEL2)
        self.option_add("*Menu.foreground", C_TXT)
        self.option_add("*Menu.activeBackground", C_ACCENT)
        self.option_add("*Menu.activeForeground", "#06101d")
        self.option_add("*Menu.borderWidth", 0)
        self.option_add("*Menu.relief", "flat")

        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure(".", background=C_BG, foreground=C_TXT,
                    fieldbackground=C_PANEL2, bordercolor=C_LINE,
                    font=("Segoe UI", 10))
        s.configure("TFrame", background=C_BG)
        s.configure("TLabel", background=C_BG, foreground=C_TXT)
        s.configure("Dim.TLabel", background=C_BG, foreground=C_TXT_DIM)
        s.configure("H2.TLabel", background=C_BG, foreground=C_TXT,
                    font=("Segoe UI Semibold", 11))
        s.configure("Treeview", background=C_PANEL, fieldbackground=C_PANEL,
                    foreground=C_TXT, rowheight=28, borderwidth=0)
        s.configure("Treeview.Heading", background=C_PANEL2, foreground=C_TXT_DIM,
                    relief="flat", font=("Segoe UI Semibold", 9))
        s.map("Treeview.Heading", background=[("active", C_LINE)])
        s.map("Treeview", background=[("selected", "#2f4a6d")],
              foreground=[("selected", C_TXT)])

        s.configure("TEntry", fieldbackground=C_PANEL2, foreground=C_TXT,
                    insertcolor=C_TXT, bordercolor=C_LINE, lightcolor=C_LINE,
                    darkcolor=C_LINE, padding=4)
        s.map("TEntry", bordercolor=[("focus", C_ACCENT)],
              lightcolor=[("focus", C_ACCENT)], darkcolor=[("focus", C_ACCENT)])

        s.configure("TCombobox", fieldbackground=C_PANEL2, background=C_PANEL2,
                    foreground=C_TXT, arrowcolor=C_ACCENT, bordercolor=C_LINE,
                    lightcolor=C_LINE, darkcolor=C_LINE, padding=4,
                    selectbackground=C_PANEL2, selectforeground=C_TXT)
        s.map("TCombobox",
              fieldbackground=[("readonly", C_PANEL2), ("disabled", C_PANEL)],
              background=[("readonly", C_PANEL2), ("active", C_PANEL2)],
              foreground=[("readonly", C_TXT), ("disabled", C_TXT_DIM)],
              selectbackground=[("readonly", C_PANEL2)],
              selectforeground=[("readonly", C_TXT)],
              bordercolor=[("focus", C_ACCENT)],
              lightcolor=[("focus", C_ACCENT)], darkcolor=[("focus", C_ACCENT)],
              arrowcolor=[("disabled", C_TXT_DIM), ("!disabled", C_ACCENT)])

        s.configure("TCheckbutton", background=C_PANEL, foreground=C_TXT,
                    indicatorcolor=C_PANEL2, focuscolor=C_PANEL)
        s.map("TCheckbutton",
              background=[("active", C_PANEL)],
              indicatorcolor=[("selected", C_OK), ("!selected", C_PANEL2)],
              foreground=[("active", C_TXT)])

        s.configure("Vertical.TScrollbar", background=C_PANEL2, troughcolor=C_BG,
                    bordercolor=C_BG, arrowcolor=C_TXT_DIM, relief="flat")
        s.map("Vertical.TScrollbar", background=[("active", C_LINE)])

    def _btn(self, parent, text, cmd, kind="normal"):
        pal = {"normal": (C_PANEL2, C_TXT), "accent": (C_ACCENT, "#06101d"),
               "ok": (C_OK, "#06251a"), "warn": (C_WARN, "#2a1c00"),
               "danger": (C_DANGER, "#2a0808")}[kind]
        return tk.Button(parent, text=text, command=cmd, bg=pal[0], fg=pal[1],
                         activebackground=pal[0], activeforeground=pal[1],
                         relief="flat", bd=0, font=("Segoe UI Semibold", 9),
                         padx=14, pady=7, cursor="hand2", highlightthickness=0)

    # ------------------------------------------------------------------ UI
    def _build(self):
        self._build_header()
        # La barre d'etat est posee AVANT la zone extensible : sinon celle-ci
        # prend toute la place disponible et repousse la barre hors de la fenetre
        # des que la fiche du bas s'agrandit.
        self._build_status()
        self.body = ttk.Frame(self)
        # La zone principale doit etre placee AVANT la barre de profils :
        # celle-ci s'insere "avant" elle, ce qui exige qu'elle soit deja posee.
        self.body.pack(fill="both", expand=True, padx=16, pady=(4, 6))
        self._build_apps(self.body)
        self._build_profiles()

    def _build_header(self):
        head = tk.Frame(self, bg=C_PANEL)
        head.pack(fill="x", padx=16, pady=(16, 8))

        left = tk.Frame(head, bg=C_PANEL)
        left.pack(side="left", fill="both", expand=True, padx=22, pady=16)
        self.lbl_used = tk.Label(left, text="0 Mo", bg=C_PANEL, fg=C_TXT,
                                 font=("Segoe UI Semibold", 26))
        self.lbl_used.pack(anchor="w")
        self.lbl_quota = tk.Label(left, text="", bg=C_PANEL, fg=C_TXT_DIM,
                                  font=("Segoe UI", 10))
        self.lbl_quota.pack(anchor="w")
        self.bar = tk.Canvas(left, height=14, bg=C_PANEL, highlightthickness=0)
        self.bar.pack(fill="x", pady=(12, 6))
        self.lbl_reset = tk.Label(left, text="", bg=C_PANEL, fg=C_TXT_DIM,
                                  font=("Segoe UI", 9))
        self.lbl_reset.pack(anchor="w")
        self.lbl_debit = tk.Label(left, text="", bg=C_PANEL, fg=C_ACCENT,
                                  font=("Segoe UI Semibold", 9))
        self.lbl_debit.pack(anchor="w", pady=(4, 0))

        right = tk.Frame(head, bg=C_PANEL)
        right.pack(side="right", padx=22, pady=16)
        self.lbl_shield = tk.Label(right, text="", bg=C_PANEL, fg=C_WARN,
                                   font=("Segoe UI Semibold", 11))
        self.lbl_shield.pack(anchor="e")
        self.lbl_engine = tk.Label(right, text="", bg=C_PANEL, fg=C_TXT_DIM,
                                   font=("Segoe UI", 9))
        self.lbl_engine.pack(anchor="e", pady=(2, 12))
        row = tk.Frame(right, bg=C_PANEL)
        row.pack(anchor="e")
        self.btn_engage = self._btn(row, "Activer la protection", self.toggle_engage, "accent")
        self.btn_engage.pack(side="left", padx=(0, 8))
        self._btn(row, "Reglages", self.open_settings).pack(side="left", padx=(0, 8))
        self._btn(row, "Aide  F1", self.show_help).pack(side="left", padx=(0, 8))
        self._btn(row, "PANIQUE", self.panic, "danger").pack(side="left")

    def _build_profiles(self):
        self.profile_wrap = ttk.Frame(self)
        self.profile_title = ttk.Label(self.profile_wrap,
                                       text="Profil actif",
                                       style="H2.TLabel")
        self.profile_title.pack(anchor="w", pady=(2, 6))
        self.profile_row = tk.Frame(self.profile_wrap, bg=C_BG)
        self.profile_row.pack(fill="x")
        self.rebuild_profile_cards()

    def rebuild_profile_cards(self):
        """La barre de profils n'apparait que si l'utilisateur en a cree
        plusieurs dans les reglages."""
        for child in self.profile_row.winfo_children():
            child.destroy()
        self.profile_cards = {}
        sm = self.state_mgr
        if not sm.multi_profiles():
            self.profile_wrap.pack_forget()
            return
        self.profile_wrap.pack(fill="x", padx=16, before=self.body)
        for pid in sm.profile_ids():
            prof = sm.data["profiles"][pid]
            card = tk.Frame(self.profile_row, bg=C_PANEL, cursor="hand2",
                            highlightthickness=2, highlightbackground=C_PANEL,
                            highlightcolor=C_PANEL)
            card.pack(side="left", fill="both", expand=True, padx=(0, 8))
            dot = tk.Frame(card, bg=prof["color"], height=4)
            dot.pack(fill="x")
            lname = tk.Label(card, text=prof["name"], bg=C_PANEL, fg=C_TXT,
                             font=("Segoe UI Semibold", 11))
            lname.pack(anchor="w", padx=12, pady=(7, 0))
            lstat = tk.Label(card, text="", bg=C_PANEL, fg=C_TXT_DIM,
                             font=("Segoe UI", 8))
            lstat.pack(anchor="w", padx=12, pady=(0, 8))
            self.profile_cards[pid] = {"frame": card, "stat": lstat,
                                       "name": lname, "dot": dot}
            for wdg in (card, lname, lstat, dot):
                wdg.bind("<Button-1>", lambda e, p=pid: self.set_profile(p))

    def _build_apps(self, parent):
        f = ttk.Frame(parent)
        f.pack(fill="both", expand=True)
        # Ordre de placement : les elements a hauteur fixe sont reserves en
        # premier (haut puis bas), le tableau prend ce qui reste. Sans cela,
        # Tk sacrifie ce qui est pose en dernier des que la place manque.
        top = ttk.Frame(f)
        top.pack(side="top", fill="x", pady=(10, 6))
        self.lbl_apps = ttk.Label(top, text="", style="H2.TLabel")
        self.lbl_apps.pack(side="left")
        self._btn(top, "Ajouter un programme...", self.add_program).pack(side="right")

        bar = ttk.Frame(f)
        bar.pack(side="bottom", fill="x", pady=(8, 0))
        self._btn(bar, "Autoriser", lambda: self.decide(True), "ok").pack(side="left")
        self._btn(bar, "Bloquer", lambda: self.decide(False), "danger").pack(side="left", padx=8)
        self._btn(bar, "Retirer de la liste", self.remove_app).pack(side="left")
        ttk.Label(bar, text="(double-clic = bascule)", style="Dim.TLabel").pack(side="left", padx=10)

        # Fiche descriptive : hauteur bloquee pour qu'un texte long ne pousse
        # jamais le reste de la fenetre. Le retour a la ligne suit la largeur
        # reelle au lieu d'une valeur figee.
        card = tk.Frame(f, bg=C_PANEL2, height=116)
        card.pack(side="bottom", fill="x", pady=(8, 0))
        card.pack_propagate(False)
        self.info_card = card
        self.lbl_info_titre = tk.Label(card, text="Selectionne une application pour "
                                                  "savoir de quoi il s'agit",
                                       bg=C_PANEL2, fg=C_TXT, anchor="w",
                                       font=("Segoe UI Semibold", 10))
        self.lbl_info_titre.pack(fill="x", padx=14, pady=(11, 0))
        self.lbl_info_corps = tk.Label(card, text="", bg=C_PANEL2, fg=C_TXT_DIM,
                                       anchor="nw", justify="left", wraplength=560,
                                       font=("Segoe UI", 9))
        self.lbl_info_corps.pack(fill="both", expand=True, padx=14, pady=(3, 10))
        card.bind("<Configure>", self._fit_info_card)

        cols = ("app", "acces", "conso", "path")
        heads = (("app", "Application", 240, "w"),
                 ("acces", "Acces", 110, "center"),
                 ("conso", "Consomme", 110, "e"),
                 ("path", "Emplacement", 380, "w"))
        self.tv_apps = ttk.Treeview(f, columns=cols, show="headings", selectmode="browse")
        for c, t, w, a in heads:
            self.tv_apps.heading(c, text=t, command=(lambda k=c: self.sort_apps(k)))
            self.tv_apps.column(c, width=w, anchor=a, stretch=(c == "path"))
        self.tv_apps.tag_configure("allow", foreground=C_OK)
        self.tv_apps.tag_configure("block", foreground=C_DANGER)
        self.tv_apps.tag_configure("wait", foreground=C_WARN)
        self.tv_apps.bind("<Double-1>", lambda e: self.toggle_app())
        self.tv_apps.bind("<<TreeviewSelect>>", lambda e: self.show_app_info())
        self.tv_apps.pack(side="top", fill="both", expand=True)

    def _build_status(self):
        sb = tk.Frame(self, bg=C_PANEL2, height=26)
        sb.pack(fill="x", side="bottom")
        self.lbl_status = tk.Label(sb, text="Pret", bg=C_PANEL2, fg=C_TXT_DIM,
                                   font=("Segoe UI", 9), anchor="w", padx=14)
        self.lbl_status.pack(side="left", fill="x", expand=True)
        tk.Label(sb, text="%s %s    %s" % (APP_NAME, VERSION_TXT, COPYRIGHT),
                 bg=C_PANEL2, fg=C_TXT_DIM,
                 font=("Segoe UI", 8), anchor="e", padx=14).pack(side="right")
        self.lbl_pending = tk.Label(sb, text="", bg=C_PANEL2, fg=C_WARN,
                                    font=("Segoe UI", 9), anchor="e", padx=14)
        self.lbl_pending.pack(side="right")

    def status(self, msg):
        self.lbl_status.configure(text=msg)

    # ----------------------------------------------------- fenetre / tray
    def report_callback_exception(self, exc, val, tb):
        """Une erreur dans un bouton ou une boucle ne doit pas tuer NetGate
        en silence : on journalise et on continue."""
        log_error("erreur d'interface", (exc, val, tb))
        try:
            self.status("Erreur interne (details dans netgate.log) : %s" % val)
        except Exception:
            pass

    def refresh_window_icon(self):
        """Regenere l'icone de la fenetre et de la barre des taches quand le
        profil ou le palier de consommation change."""
        sm = self.state_mgr
        pct = sm.total_used() / float(sm.quota_bytes())
        sig = (sm.data["active_profile"], int(min(1.0, pct) * 20))
        if sig == self._icon_sig:
            return
        self._icon_sig = sig
        path = write_ico(sm.profile_color(), pct)
        if path:
            try:
                self.iconbitmap(default=path)
            except Exception:
                try:
                    self.iconbitmap(path)
                except Exception:
                    pass

    def hide_window(self):
        if self.tray.available:
            self.withdraw()
            self.tray.notify(APP_NAME, "NetGate continue de surveiller en arriere-plan.")
            self.status("Reduit dans la zone de notification")
        else:
            self.iconify()

    def show_window(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def quit_app(self):
        """En quittant, NetGate remet toujours Internet dans son etat normal :
        politique sortante par defaut et suppression de toutes les regles
        NETGATE_. Aucune question, rien ne peut rester bloque."""
        d = self.state_mgr.data
        try:
            Firewall.panic_restore(self._all_known_paths())
            log_line("fermeture : regles NETGATE_ supprimees, sortant retabli")
        except Exception:
            log_error("nettoyage du pare-feu a la fermeture")
        d["engaged"] = False
        self.state_mgr.save()
        self.meter.stop()
        self.scanner.stop()
        self.tray.stop()
        self.destroy()

    # -------------------------------------------------------------- moteur
    def _all_known_paths(self):
        paths = set(self.state_mgr.data["catalog"].keys())
        for prof in self.state_mgr.data["profiles"].values():
            paths |= set(prof.get("apps", {}).keys())
        return paths

    def apply_firewall(self, full=False):
        """Ne touche que ce qui change, et travaille en arriere-plan pour que
        l'interface reponde immediatement."""
        with self._fw_lock:
            self._fw_pending = True
            self._fw_full = self._fw_full or full
            if self._fw_busy:
                return
            self._fw_busy = True
        self.status("Application des regles...")
        threading.Thread(target=self._fw_worker, daemon=True, name="Firewall").start()

    def _fw_worker(self):
        while True:
            with self._fw_lock:
                if not self._fw_pending:
                    self._fw_busy = False
                    return
                self._fw_pending = False
                full = self._fw_full
                self._fw_full = False
            try:
                msg = self._fw_sync(full)
            except Exception:
                log_error("application des regles au pare-feu")
                msg = "Erreur pare-feu, voir netgate.log"
            self.after(0, lambda m=msg: self.status(m))

    def _fw_sync(self, full):
        sm = self.state_mgr
        d = sm.data
        debut = time.time()

        if not d["engaged"]:
            lines = list(Firewall.line_lockdown(False))
            for p in (self._all_known_paths() if full else self.applied):
                lines += Firewall.line_delete(p)
            lines += Firewall.lines_essentials(False)
            Firewall.run_script(lines)
            self.applied = set()
            return "Protection desactivee"

        if sm.profile.get("allow_all"):
            lines = list(Firewall.line_lockdown(False))
            for p in (self._all_known_paths() if full else self.applied):
                lines += Firewall.line_delete(p)
            Firewall.run_script(lines)
            self.applied = set()
            return "Profil %s : aucun filtrage, le compteur tourne" % sm.profile_name()

        if not sm.schedule_open():
            souhaite = set()          # hors plage horaire : plus rien ne sort
        else:
            souhaite = set(sm.allowed_paths())
        if full:
            a_retirer = self._all_known_paths() - souhaite
            a_ajouter = souhaite
        else:
            a_retirer = self.applied - souhaite
            a_ajouter = souhaite - self.applied

        lines = []
        for p in a_retirer:
            lines += Firewall.line_delete(p)
        for p in a_ajouter:
            lines += Firewall.line_allow(p, self.state_mgr.data["catalog"]
                                         .get(p, {}).get("name", ""))
        if full:
            lines += Firewall.lines_essentials(bool(d["essentials_dns"]))
        lines += Firewall.line_lockdown(True)

        Firewall.run_script(lines)
        self.applied = souhaite
        delai = time.time() - debut
        if not sm.schedule_open():
            suite = sm.schedule_next_change()
            return ("Hors plage horaire : Internet coupe" +
                    (" jusqu'a %s" % suite[1] if suite else ""))
        if not a_retirer and not a_ajouter:
            return "Protection active - %d programmes autorises" % len(souhaite)
        return ("Regles a jour : %d ajoutees, %d retirees (%.1f s)"
                % (len(a_ajouter), len(a_retirer), delai))

    def toggle_engage(self):
        d = self.state_mgr.data
        d["engaged"] = not d["engaged"]
        if d["engaged"] and not d["essentials_dns"]:
            if messagebox.askyesno("Protection",
                                   "Activer aussi la regle DNS/DHCP ? Sans elle, "
                                   "aucun site ne pourra etre trouve, meme pour les "
                                   "applications autorisees."):
                d["essentials_dns"] = True
        self.apply_firewall(full=True)
        self.state_mgr.save()

    def set_profile(self, pid):
        sm = self.state_mgr
        if pid not in sm.data["profiles"] or pid == sm.data["active_profile"]:
            return
        sm.data["active_profile"] = pid
        self.scanner.reset_asked()
        # l'ecran se met a jour tout de suite ; le pare-feu suit en arriere-plan
        self.refresh_all()
        self.refresh_window_icon()
        self.tray.refresh()
        self.update_idletasks()
        self.apply_firewall()
        sm.save()

    def panic(self):
        if not messagebox.askyesno("Tout debloquer",
                                   "Retablir Internet normalement et supprimer "
                                   "toutes les regles NetGate ?"):
            return
        Firewall.panic_restore(self._all_known_paths())
        self.state_mgr.data["engaged"] = False
        self.state_mgr.save()
        self.status("Internet retabli, regles NetGate supprimees.")

    # --------------------------------------------------------- decisions
    def apply_decision(self, path, allow):
        sm = self.state_mgr
        sm.set_app(path, allow)
        if sm.data["engaged"]:
            self.apply_firewall()
        self.pending = [p for p in self.pending if p["path"].lower() != path.lower()]
        sm.save()
        self.refresh_apps()
        self.status("%s : %s dans le profil %s"
                    % (os.path.basename(path), "autorise" if allow else "bloque",
                       sm.profile_name()))

    def on_toast_decision(self, item, value):
        self.toast = None
        if value is None:
            if item not in self.pending:
                self.pending.append(item)
            self.refresh_pending_label()
        else:
            self.apply_decision(item["path"], value)
        self.after(300, self._show_next_toast)

    def _show_next_toast(self):
        if self.toast is not None or not self.state_mgr.data["notify_enabled"]:
            return
        while self.pending:
            item = self.pending[0]
            if item["path"].lower() in self.state_mgr.profile["apps"]:
                self.pending.pop(0)
                continue
            break
        if not self.pending:
            return
        item = self.pending.pop(0)
        lifetime = self.state_mgr.data["catalog"].get(
            item["path"].lower(), {}).get("lifetime", 0)
        try:
            self.toast = AuthToast(self, item, self.state_mgr.profile_color(),
                                   int(self.state_mgr.data["notify_timeout"]),
                                   self.on_toast_decision, lifetime=lifetime)
        except Exception:
            self.toast = None

    def selected_path(self):
        sel = self.tv_apps.selection()
        if not sel:
            return None
        return self.tv_apps.item(sel[0], "values")[3]

    def label_for(self, path):
        """Nom comprehensible : description du fichier, sinon glossaire,
        sinon nom brut. Mis en cache dans le catalogue."""
        if not path or path.startswith("("):
            return "Trafic non attribue" if path else "?"
        key = path.lower()
        cat = self.state_mgr.data["catalog"].get(key)
        if cat and cat.get("label"):
            return cat["label"]
        try:
            lab = Inspector.fast(path, None)["titre"] or os.path.basename(path)
        except Exception:
            lab = os.path.basename(path)
        if cat is not None:
            cat["label"] = lab
        return lab

    def open_schedule(self, parent=None):
        """Tableau des 48 demi-heures de la journee. Une case cochee = Internet
        autorise pendant cette demi-heure."""
        sm = self.state_mgr
        w = tk.Toplevel(parent or self)
        w.title("Plages horaires")
        w.configure(bg=C_PANEL)
        w.resizable(False, False)
        w.transient(parent or self)
        w.grab_set()

        frm = tk.Frame(w, bg=C_PANEL)
        frm.pack(padx=24, pady=20)

        v_actif = tk.BooleanVar(value=bool(sm.data.get("schedule_enabled")))
        cases = [tk.BooleanVar(value=(c == "1")) for c in sm.schedule()]

        tk.Label(frm, text="Plages horaires", bg=C_PANEL, fg=C_TXT,
                 font=("Segoe UI Semibold", 13)).pack(anchor="w")
        tk.Label(frm, bg=C_PANEL, fg=C_TXT_DIM, justify="left", wraplength=560,
                 font=("Segoe UI", 9),
                 text=("Coche les demi-heures pendant lesquelles Internet est "
                       "autorise. En dehors, plus rien ne sort, meme les programmes "
                       "de ta liste. Les memes horaires s'appliquent tous les jours.")
                 ).pack(anchor="w", pady=(2, 10))

        ttk.Checkbutton(frm, text="Limiter Internet aux plages cochees ci-dessous",
                        variable=v_actif).pack(anchor="w", pady=(0, 12))

        # deux colonnes de 12 heures
        grille = tk.Frame(frm, bg=C_PANEL)
        grille.pack()
        for bloc in (0, 1):
            col = tk.Frame(grille, bg=C_PANEL)
            col.grid(row=0, column=bloc, padx=(0, 26 if bloc == 0 else 0), sticky="n")
            tk.Label(col, text="heure", bg=C_PANEL, fg=C_TXT_DIM,
                     font=("Segoe UI", 8)).grid(row=0, column=0, sticky="w")
            tk.Label(col, text=":00", bg=C_PANEL, fg=C_TXT_DIM,
                     font=("Segoe UI", 8)).grid(row=0, column=1, padx=6)
            tk.Label(col, text=":30", bg=C_PANEL, fg=C_TXT_DIM,
                     font=("Segoe UI", 8)).grid(row=0, column=2, padx=6)
            for ligne in range(12):
                h = bloc * 12 + ligne
                tk.Label(col, text="%02dh" % h, bg=C_PANEL, fg=C_TXT,
                         font=("Consolas", 9)).grid(row=ligne + 1, column=0, sticky="w",
                                                    pady=1)
                for demi in (0, 1):
                    ttk.Checkbutton(col, variable=cases[h * 2 + demi]).grid(
                        row=ligne + 1, column=1 + demi, padx=6)

        resume = tk.Label(frm, bg=C_PANEL, fg=C_ACCENT, font=("Segoe UI Semibold", 10))
        resume.pack(anchor="w", pady=(14, 0))

        def maj_resume(*_):
            n = sum(1 for v in cases if v.get())
            if n == 48:
                resume.configure(text="Internet autorise 24 h sur 24", fg=C_OK)
            elif n == 0:
                resume.configure(text="Internet coupe en permanence", fg=C_DANGER)
            else:
                resume.configure(text="Internet autorise %g h par jour" % (n / 2.0),
                                 fg=C_ACCENT)

        for v in cases:
            v.trace_add("write", maj_resume)
        maj_resume()

        def remplir(debut, fin):
            for i in range(48):
                cases[i].set(debut <= i < fin)

        outils = tk.Frame(frm, bg=C_PANEL)
        outils.pack(anchor="w", pady=(12, 0))
        self._btn(outils, "Tout ouvrir", lambda: remplir(0, 48)).pack(side="left")
        self._btn(outils, "Tout fermer", lambda: remplir(0, 0)).pack(side="left", padx=8)
        self._btn(outils, "08h - 22h", lambda: remplir(16, 44)).pack(side="left")
        self._btn(outils, "Inverser",
                  lambda: [v.set(not v.get()) for v in cases]).pack(side="left", padx=8)

        def enregistrer():
            sm.data["schedule"] = "".join("1" if v.get() else "0" for v in cases)
            sm.data["schedule_enabled"] = bool(v_actif.get())
            sm.save()
            self._slot_state = None          # force la reevaluation
            self.apply_firewall()
            self.refresh_all()
            w.destroy()

        bar = tk.Frame(frm, bg=C_PANEL)
        bar.pack(fill="x", pady=(16, 0))
        self._btn(bar, "Annuler", w.destroy).pack(side="right", padx=(8, 0))
        self._btn(bar, "Enregistrer", enregistrer, "accent").pack(side="right")

    def reset_counter(self, parent=None):
        """Repart de zero pour la periode en cours. Les autorisations et
        l'historique ne sont pas touches."""
        sm = self.state_mgr
        hote = parent or self
        if sm.total_used() == 0:
            messagebox.showinfo("Compteur", "Le compteur est deja a zero.", parent=hote)
            return
        if not messagebox.askyesno(
                "Remettre le compteur a zero",
                "Le compteur repartira de 0 sur %d Mo.\n\n"
                "Consomme actuellement : %s\n\n"
                "Tes autorisations et l'historique sont conserves."
                % (sm.data["quota_mb"], fmt_bytes(sm.total_used())), parent=hote):
            return
        ancien = sm.total_used()
        sm.data["usage"] = {"period": sm.period_key(), "per_app": {},
                            "per_profile": {}, "per_hour": {},
                            "total_sent": 0, "total_recv": 0,
                            "off_sent": 0, "off_recv": 0}
        sm.data["alerts_fired"] = []
        self.rates = {}
        self._icon_sig = None
        sm.save()
        self.refresh_all()
        self.refresh_window_icon()
        self.tray.refresh()
        try:
            self.lbl_cfg_conso.configure(text="  consomme aujourd'hui : %s"
                                              % fmt_bytes(sm.total_used()))
        except Exception:
            pass
        self.status("Compteur remis a zero (%s efface)" % fmt_bytes(ancien))

    def show_help(self, event=None):
        if getattr(self, "help_win", None) is not None:
            try:
                self.help_win.lift()
                self.help_win.focus_force()
                return
            except Exception:
                self.help_win = None

        w = tk.Toplevel(self)
        self.help_win = w
        w.title("Aide de %s %s" % (APP_NAME, VERSION_TXT))
        w.geometry("760x640")
        w.minsize(620, 480)
        w.configure(bg=C_BG)

        def close(*_):
            self.help_win = None
            w.destroy()

        w.protocol("WM_DELETE_WINDOW", close)
        w.bind("<Escape>", close)

        head = tk.Frame(w, bg=C_PANEL)
        head.pack(fill="x")
        tete = tk.Frame(head, bg=C_PANEL)
        tete.pack(side="left", padx=22, pady=12)
        tk.Label(tete, text="Aide de %s %s" % (APP_NAME, VERSION_TXT),
                 bg=C_PANEL, fg=C_TXT,
                 font=("Segoe UI Semibold", 15)).pack(anchor="w")
        tk.Label(tete, text=COPYRIGHT, bg=C_PANEL, fg=C_TXT_DIM,
                 font=("Segoe UI", 9)).pack(anchor="w")
        tk.Label(head, text="Echap ou F1 pour fermer", bg=C_PANEL, fg=C_TXT_DIM,
                 font=("Segoe UI", 9)).pack(side="right", padx=22)

        zone = tk.Frame(w, bg=C_BG)
        zone.pack(fill="both", expand=True)
        txt = tk.Text(zone, bg=C_BG, fg=C_TXT, relief="flat", wrap="word",
                      padx=26, pady=18, bd=0, highlightthickness=0,
                      font=("Segoe UI", 10), spacing1=2, spacing3=6, cursor="arrow")
        sb = ttk.Scrollbar(zone, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        txt.tag_configure("h1", font=("Segoe UI Semibold", 13), foreground=C_ACCENT,
                          spacing1=16, spacing3=6)
        txt.tag_configure("h2", font=("Segoe UI Semibold", 10), foreground=C_TXT,
                          spacing1=8, spacing3=2)
        txt.tag_configure("p", foreground=C_TXT, lmargin1=2, lmargin2=2)
        txt.tag_configure("warn", foreground=C_WARN, lmargin1=12, lmargin2=12,
                          spacing1=8, spacing3=8)
        txt.tag_configure("code", font=("Consolas", 10), foreground=C_OK,
                          lmargin1=12, lmargin2=12)

        for tag, body in HELP:
            if tag == "about":
                txt.insert("end", "%s %s\n" % (APP_NAME, VERSION_TXT), "p")
                txt.insert("end", COPYRIGHT + "\n", "code")
                continue
            if tag == "code" and body == "@DOSSIER@":
                txt.insert("end", STATE_DIR + "\n", "code")
                continue
            txt.insert("end", body + "\n", tag)
        txt.configure(state="disabled")
        txt.bind("<F1>", close)

    def open_folder(self):
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            os.startfile(STATE_DIR)
        except Exception as e:
            messagebox.showerror("Dossier", str(e))

    def reset_choices(self, parent=None):
        """Efface uniquement les autorisations de la liste active."""
        sm = self.state_mgr
        n = len(sm.profile["apps"])
        if not n:
            messagebox.showinfo("Choix", "Aucun choix enregistre pour l'instant.",
                                parent=parent or self)
            return
        if not messagebox.askyesno(
                "Reinitialiser les choix",
                "Effacer les %d decisions de la liste \"%s\" ?\n\n"
                "NetGate te reposera la question a chaque programme."
                % (n, sm.profile_name()), parent=parent or self):
            return
        sm.profile["apps"] = {}
        self.pending = []
        self.scanner.reset_asked()
        self.apply_firewall(full=True)
        sm.save()
        self.refresh_all()
        self.status("Choix effaces pour \"%s\"" % sm.profile_name())

    def open_reset(self, parent=None):
        """Choix de ce qu'on efface, du plus doux au plus radical."""
        w = tk.Toplevel(parent or self)
        w.title("Effacer des donnees")
        w.configure(bg=C_PANEL)
        w.resizable(False, False)
        w.transient(parent or self)
        w.grab_set()
        frm = tk.Frame(w, bg=C_PANEL)
        frm.pack(padx=26, pady=22)

        tk.Label(frm, text="Que veux-tu effacer ?", bg=C_PANEL, fg=C_TXT,
                 font=("Segoe UI Semibold", 12)).pack(anchor="w", pady=(0, 12))

        v_jour = tk.BooleanVar(value=False)
        v_hist = tk.BooleanVar(value=False)
        v_apps = tk.BooleanVar(value=False)
        v_tout = tk.BooleanVar(value=False)

        for var, titre, desc in (
            (v_jour, "Les compteurs d'aujourd'hui",
             "Repart de 0 Mo pour la journee en cours. Les autorisations sont gardees."),
            (v_hist, "L'historique des jours passes",
             "Efface les statistiques des journees precedentes."),
            (v_apps, "Toutes les autorisations",
             "Vide la liste des programmes connus. NetGate te reposera la question "
             "a chaque programme."),
            (v_tout, "TOUT remettre a neuf",
             "Supprime le fichier de reglages, efface les regles du pare-feu et "
             "revient a l'etat du premier lancement."),
        ):
            box = tk.Frame(frm, bg=C_PANEL)
            box.pack(fill="x", pady=(0, 10))
            ttk.Checkbutton(box, text=titre, variable=var).pack(anchor="w")
            tk.Label(box, text=desc, bg=C_PANEL, fg=C_TXT_DIM, justify="left",
                     wraplength=420, font=("Segoe UI", 8)).pack(anchor="w", padx=24)

        tk.Label(frm, bg=C_PANEL, fg=C_WARN, justify="left", wraplength=430,
                 font=("Segoe UI", 8),
                 text=("La protection sera desactivee et les regles NETGATE_ du "
                       "pare-feu supprimees des que les autorisations sont effacees : "
                       "Internet redevient normal, tu pourras reactiver ensuite.")
                 ).pack(anchor="w", pady=(4, 12))

        def go():
            if not any(v.get() for v in (v_jour, v_hist, v_apps, v_tout)):
                w.destroy()
                return
            quoi = "TOUT remettre a neuf" if v_tout.get() else "les elements coches"
            if not messagebox.askyesno("Confirmation",
                                       "Effacer %s ?\n\nCette action est definitive."
                                       % quoi, parent=w):
                return
            self.do_reset(v_jour.get(), v_hist.get(), v_apps.get(), v_tout.get())
            w.destroy()

        bar = tk.Frame(frm, bg=C_PANEL)
        bar.pack(fill="x")
        self._btn(bar, "Annuler", w.destroy).pack(side="right", padx=(8, 0))
        self._btn(bar, "Effacer", go, "danger").pack(side="right")

    def do_reset(self, jour, hist, apps, tout):
        sm = self.state_mgr
        if apps or tout:
            Firewall.panic_restore(self._all_known_paths())
            sm.data["engaged"] = False
        if tout:
            try:
                os.remove(STATE_FILE)
            except Exception:
                pass
            sm.data = json.loads(json.dumps(DEFAULT_STATE))
        else:
            if jour:
                sm.data["usage"] = {"period": sm.period_key(), "per_app": {},
                                    "per_profile": {}, "per_hour": {},
                                    "total_sent": 0, "total_recv": 0,
                                    "off_sent": 0, "off_recv": 0}
                sm.data["alerts_fired"] = []
            if hist:
                sm.data["history"] = {}
            if apps:
                for prof in sm.data["profiles"].values():
                    prof["apps"] = {}
                sm.data["catalog"] = {}
        self.pending = []
        self.rates = {}
        self.scanner.reset_asked()
        Inspector._ver_cache.clear()
        Inspector._sig_cache.clear()
        Inspector._dns_cache.clear()
        self._icon_sig = None
        sm.save()
        self.rebuild_profile_cards()
        self.refresh_all()
        self.refresh_window_icon()
        self.tray.refresh()
        self.status("Donnees effacees" + (" - NetGate est revenu a neuf" if tout else ""))

    def open_profiles(self, parent=None):
        """Creation et gestion des profils. Facultatif : une seule liste
        suffit dans la plupart des cas."""
        from tkinter import simpledialog, colorchooser

        sm = self.state_mgr
        w = tk.Toplevel(parent or self)
        w.title("Profils")
        w.configure(bg=C_PANEL)
        w.geometry("620x460")
        w.transient(parent or self)
        w.grab_set()

        tk.Label(w, text="Profils", bg=C_PANEL, fg=C_TXT,
                 font=("Segoe UI Semibold", 13)).pack(anchor="w", padx=22, pady=(18, 2))
        tk.Label(w, bg=C_PANEL, fg=C_TXT_DIM, justify="left", wraplength=560,
                 font=("Segoe UI", 9),
                 text=("Un profil = une liste d'applications autorisees, pour un usage "
                       "donne. Avec un seul profil, NetGate reste simple et la barre de "
                       "choix n'apparait pas sur l'ecran principal.")
                 ).pack(anchor="w", padx=22, pady=(0, 12))

        tv = ttk.Treeview(w, columns=("n", "a", "b"), show="headings", height=8)
        for c, t, wd, a in (("n", "Nom", 260, "w"), ("a", "Applications", 110, "center"),
                            ("b", "Budget", 100, "e")):
            tv.heading(c, text=t)
            tv.column(c, width=wd, anchor=a)
        tv.pack(fill="both", expand=True, padx=22)

        ids = []

        def reload_list():
            ids.clear()
            tv.delete(*tv.get_children())
            for pid in sm.profile_ids():
                p = sm.data["profiles"][pid]
                ids.append(pid)
                mark = "  (actif)" if pid == sm.data["active_profile"] else ""
                tv.insert("", "end", values=(
                    p["name"] + mark,
                    "tout" if p.get("allow_all") else str(len(p["apps"])),
                    ("%d Mo" % p["budget_mb"]) if p.get("budget_mb") else "-"))
            self.rebuild_profile_cards()
            self.refresh_all()
            self.tray.refresh()
            sm.save()

        def current():
            sel = tv.selection()
            return ids[tv.index(sel[0])] if sel else None

        def add(preset=None):
            if preset:
                name = preset
                color, desc, budget, allow_all = PRESET_PROFILES[preset]
            else:
                name = simpledialog.askstring("Nouveau profil", "Nom du profil :",
                                              parent=w)
                if not name:
                    return
                color, desc, budget, allow_all = C_ACCENT, "", 0, False
            pid = slugify(name)
            if pid in sm.data["profiles"]:
                messagebox.showerror("Profil", "Ce nom existe deja.", parent=w)
                return
            sm.data["profiles"][pid] = {"name": name, "color": color, "desc": desc,
                                        "budget_mb": budget, "allow_all": allow_all,
                                        "apps": {}}
            reload_list()

        def rename():
            pid = current()
            if not pid:
                return
            new = simpledialog.askstring("Renommer", "Nouveau nom :", parent=w,
                                         initialvalue=sm.data["profiles"][pid]["name"])
            if new:
                sm.data["profiles"][pid]["name"] = new
                reload_list()

        def recolor():
            pid = current()
            if not pid:
                return
            c = colorchooser.askcolor(color=sm.data["profiles"][pid]["color"],
                                      parent=w, title="Couleur du profil")
            if c and c[1]:
                sm.data["profiles"][pid]["color"] = c[1]
                self._icon_sig = None
                reload_list()

        def budget():
            pid = current()
            if not pid:
                return
            v = simpledialog.askinteger("Budget", "Budget indicatif en Mo (0 = aucun) :",
                                        parent=w, minvalue=0, maxvalue=1000000,
                                        initialvalue=sm.data["profiles"][pid]["budget_mb"])
            if v is not None:
                sm.data["profiles"][pid]["budget_mb"] = v
                reload_list()

        def clear():
            pid = current()
            if not pid:
                return
            p = sm.data["profiles"][pid]
            if messagebox.askyesno("Vider", "Effacer les %d choix de \"%s\" ?"
                                   % (len(p["apps"]), p["name"]), parent=w):
                p["apps"] = {}
                if pid == sm.data["active_profile"]:
                    self.scanner.reset_asked()
                    self.apply_firewall(full=True)
                reload_list()

        def delete():
            pid = current()
            if not pid:
                return
            if len(sm.data["profiles"]) <= 1:
                messagebox.showerror("Profil", "Il faut garder au moins une liste.",
                                     parent=w)
                return
            if not messagebox.askyesno("Supprimer", "Supprimer \"%s\" et ses choix ?"
                                       % sm.data["profiles"][pid]["name"], parent=w):
                return
            del sm.data["profiles"][pid]
            if sm.data["active_profile"] == pid:
                sm.data["active_profile"] = sm.profile_ids()[0]
                self.scanner.reset_asked()
                self.apply_firewall(full=True)
            reload_list()

        def activate():
            pid = current()
            if pid:
                self.set_profile(pid)
                reload_list()

        bar1 = tk.Frame(w, bg=C_PANEL)
        bar1.pack(fill="x", padx=22, pady=(12, 0))
        self._btn(bar1, "Nouveau", add, "accent").pack(side="left")
        mb = tk.Menubutton(bar1, text="Depuis un modele", bg=C_PANEL2, fg=C_TXT,
                           activebackground=C_PANEL2, activeforeground=C_TXT,
                           relief="flat", bd=0, font=("Segoe UI Semibold", 9),
                           padx=14, pady=7, cursor="hand2", highlightthickness=0)
        menu = tk.Menu(mb, tearoff=0)
        for preset in PRESET_PROFILES:
            menu.add_command(label=preset, command=lambda p=preset: add(p))
        mb.configure(menu=menu)
        mb.pack(side="left", padx=8)
        self._btn(bar1, "Rendre actif", activate).pack(side="left")

        bar2 = tk.Frame(w, bg=C_PANEL)
        bar2.pack(fill="x", padx=22, pady=(8, 16))
        self._btn(bar2, "Renommer", rename).pack(side="left")
        self._btn(bar2, "Couleur", recolor).pack(side="left", padx=8)
        self._btn(bar2, "Budget", budget).pack(side="left")
        self._btn(bar2, "Vider les choix", clear, "warn").pack(side="left", padx=8)
        self._btn(bar2, "Supprimer", delete, "danger").pack(side="left")
        self._btn(bar2, "Fermer", w.destroy).pack(side="right")

        reload_list()

    def _fit_info_card(self, event=None):
        """Le texte se replie sur la largeur reelle de la fiche."""
        try:
            largeur = max(200, self.info_card.winfo_width() - 34)
            self.lbl_info_corps.configure(wraplength=largeur)
        except Exception:
            pass

    @staticmethod
    def _court(txt, n=150):
        txt = " ".join((txt or "").split())
        return txt if len(txt) <= n else txt[:n - 1].rstrip() + "\u2026"

    def show_app_info(self):
        path = self.selected_path()
        if not path:
            return
        pid = None
        for it in self.pending:
            if it["path"].lower() == path.lower():
                pid = it.get("pid")
                break
        info = Inspector.fast(path, pid)
        col, lab = NIVEAU_STYLE.get(info["niveau"], NIVEAU_STYLE["utile"])
        self.lbl_info_titre.configure(
            text=self._court(info["titre"] or os.path.basename(path), 90), fg=col)
        cat = self.state_mgr.data["catalog"].get(path.lower(), {})

        # quatre lignes au maximum : la fiche a une hauteur fixe
        lignes = ["[%s]  %s%s" % (lab, info["origine"],
                                  ("  -  " + info["editeur"]) if info["editeur"] else "")]
        if info["quoi"]:
            lignes.append(self._court(info["quoi"], 170))
        if info["conseil"]:
            lignes.append("Conseil : " + self._court(info["conseil"], 150))
        queue_txt = self._court(path, 110)
        if cat.get("lifetime"):
            queue_txt = "Total consomme : %s      %s" % (fmt_bytes(cat["lifetime"]),
                                                         self._court(path, 80))
        lignes.append(queue_txt)
        self.lbl_info_corps.configure(text="\n".join(lignes[:4]))
        self._fit_info_card()

    def decide(self, allow):
        p = self.selected_path()
        if p:
            self.apply_decision(p, allow)

    def toggle_app(self):
        p = self.selected_path()
        if not p:
            return
        cur = self.state_mgr.profile["apps"].get(p.lower(), False)
        self.apply_decision(p, not cur)

    def remove_app(self):
        p = self.selected_path()
        if not p:
            return
        self.state_mgr.forget_app(p)
        self.scanner.forget(p)
        if self.state_mgr.data["engaged"]:
            self.apply_firewall()
        self.state_mgr.save()
        self.refresh_apps()

    def add_program(self):
        p = filedialog.askopenfilename(title="Choisir un programme",
                                       filetypes=[("Programmes", "*.exe"),
                                                  ("Tous les fichiers", "*.*")])
        if p:
            self.apply_decision(os.path.normpath(p), True)

    # --------------------------------------------------------- reglages
    def open_settings(self):
        d = self.state_mgr.data
        w = tk.Toplevel(self)
        w.title("Reglages")
        w.configure(bg=C_PANEL)
        w.resizable(False, False)
        w.transient(self)
        w.grab_set()

        frm = tk.Frame(w, bg=C_PANEL)
        frm.pack(padx=26, pady=22)

        v_quota = tk.StringVar(value=str(d["quota_mb"]))
        v_reset = tk.StringVar(value="%02d:%02d" % (d["reset_hh"], d["reset_mm"]))
        v_tz = tk.StringVar(value=d["tz_mode"])
        v_dns = tk.BooleanVar(value=d["essentials_dns"])
        v_notif = tk.BooleanVar(value=d["notify_enabled"])
        v_to = tk.StringVar(value=str(d["notify_timeout"]))
        v_min = tk.BooleanVar(value=d["start_minimized"])

        rows = [
            ("Enveloppe du jour (Mo)", v_quota, None),
            ("Heure de remise a zero (HH:MM)", v_reset, None),
            ("Heure de reference", v_tz, ["local", "utc"]),
            ("Duree d'affichage des notifications (s)", v_to, None),
        ]
        r = 0
        for label, var, values in rows:
            tk.Label(frm, text=label, bg=C_PANEL, fg=C_TXT,
                     font=("Segoe UI", 10)).grid(row=r, column=0, sticky="w", pady=7)
            if values:
                ttk.Combobox(frm, textvariable=var, values=values, state="readonly",
                             width=14).grid(row=r, column=1, sticky="w", padx=12)
            else:
                ttk.Entry(frm, textvariable=var, width=16).grid(row=r, column=1,
                                                                sticky="w", padx=12)
            r += 1

        for label, var in (("Autoriser DNS/DHCP (indispensable en mode protege)", v_dns),
                           ("Afficher une notification a chaque demande", v_notif),
                           ("Demarrer reduit dans la zone de notification", v_min)):
            ttk.Checkbutton(frm, text=label, variable=var).grid(
                row=r, column=0, columnspan=2, sticky="w", pady=5)
            r += 1

        tk.Label(frm, bg=C_PANEL, fg=C_TXT_DIM, justify="left", wraplength=430,
                 font=("Segoe UI", 8),
                 text=("Aucune coupure automatique : au-dela de l'enveloppe, "
                       "NetGate previent seulement (50 %, 80 %, 100 %).")
                 ).grid(row=r, column=0, columnspan=2, sticky="w", pady=(12, 4))
        r += 1

        zplage = tk.Frame(frm, bg=C_PANEL)
        zplage.grid(row=r, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self._btn(zplage, "Plages horaires...",
                  lambda: self.open_schedule(w)).pack(side="left")
        etat_pl = ("actives, %g h par jour" % self.state_mgr.schedule_hours()
                   if self.state_mgr.data.get("schedule_enabled") else "desactivees")
        tk.Label(zplage, text="  " + etat_pl, bg=C_PANEL, fg=C_TXT_DIM,
                 font=("Segoe UI", 9)).pack(side="left")
        r += 1

        zcompt = tk.Frame(frm, bg=C_PANEL)
        zcompt.grid(row=r, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._btn(zcompt, "Remettre le compteur a zero",
                  lambda: self.reset_counter(w), "warn").pack(side="left")
        self.lbl_cfg_conso = tk.Label(zcompt, bg=C_PANEL, fg=C_TXT_DIM,
                                      font=("Segoe UI", 9),
                                      text="  consomme aujourd'hui : %s"
                                           % fmt_bytes(self.state_mgr.total_used()))
        self.lbl_cfg_conso.pack(side="left")
        r += 1

        tk.Frame(frm, bg=C_LINE, height=1).grid(row=r, column=0, columnspan=2,
                                                sticky="ew", pady=(14, 10))
        r += 1
        tk.Label(frm, text="Profils (facultatif)", bg=C_PANEL, fg=C_TXT,
                 font=("Segoe UI Semibold", 10)).grid(row=r, column=0, columnspan=2,
                                                      sticky="w")
        r += 1
        tk.Label(frm, bg=C_PANEL, fg=C_TXT_DIM, justify="left", wraplength=430,
                 font=("Segoe UI", 8),
                 text=("Par defaut, une seule liste d'autorisations. Cree plusieurs "
                       "profils ici si tu veux basculer d'un usage a l'autre "
                       "(travail, visio, blackout).")
                 ).grid(row=r, column=0, columnspan=2, sticky="w", pady=(3, 0))
        r += 1
        zprof = tk.Frame(frm, bg=C_PANEL)
        zprof.grid(row=r, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self._btn(zprof, "Gerer les profils...",
                  lambda: self.open_profiles(w)).pack(side="left")
        self._btn(zprof, "Reinitialiser les choix",
                  lambda: self.reset_choices(w), "warn").pack(side="left", padx=8)
        r += 1

        tk.Frame(frm, bg=C_LINE, height=1).grid(row=r, column=0, columnspan=2,
                                                sticky="ew", pady=(14, 10))
        r += 1
        tk.Label(frm, text="Ou sont stockes tes reglages", bg=C_PANEL, fg=C_TXT,
                 font=("Segoe UI Semibold", 10)).grid(row=r, column=0, columnspan=2,
                                                      sticky="w")
        r += 1
        tk.Label(frm, text=STATE_FILE, bg=C_PANEL, fg=C_ACCENT, justify="left",
                 wraplength=430, font=("Consolas", 8)).grid(row=r, column=0,
                                                            columnspan=2, sticky="w",
                                                            pady=(3, 0))
        r += 1
        tk.Label(frm, bg=C_PANEL, fg=C_TXT_DIM, justify="left", wraplength=430,
                 font=("Segoe UI", 8),
                 text=("Un seul fichier : profils, autorisations, compteurs et "
                       "historique. Aucune ecriture ailleurs. Les regles du pare-feu "
                       "Windows portent le prefixe NETGATE_.")
                 ).grid(row=r, column=0, columnspan=2, sticky="w", pady=(3, 0))
        r += 1
        zone = tk.Frame(frm, bg=C_PANEL)
        zone.grid(row=r, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self._btn(zone, "Ouvrir le dossier", self.open_folder).pack(side="left")
        self._btn(zone, "Effacer des donnees...",
                  lambda: self.open_reset(w), "danger").pack(side="left", padx=8)
        r += 1

        def save():
            try:
                d["quota_mb"] = max(1, int(float(v_quota.get())))
                hh, mm = v_reset.get().split(":")
                d["reset_hh"], d["reset_mm"] = int(hh) % 24, int(mm) % 60
                d["notify_timeout"] = max(5, int(float(v_to.get())))
            except Exception:
                messagebox.showerror("Reglages", "Valeur invalide.", parent=w)
                return
            d["tz_mode"] = v_tz.get()
            d["notify_enabled"] = bool(v_notif.get())
            d["start_minimized"] = bool(v_min.get())
            new_dns = bool(v_dns.get())
            if new_dns != d["essentials_dns"]:
                d["essentials_dns"] = new_dns
                Firewall.set_essentials_dns(new_dns and d["engaged"])
            self.state_mgr.roll_period_if_needed()
            self.state_mgr.save()
            self.refresh_all()
            w.destroy()
            self.status("Reglages enregistres")

        bar = tk.Frame(frm, bg=C_PANEL)
        bar.grid(row=r, column=0, columnspan=2, sticky="e", pady=(14, 0))
        self._btn(bar, "Annuler", w.destroy).pack(side="right", padx=(8, 0))
        self._btn(bar, "Enregistrer", save, "accent").pack(side="right")

    # -------------------------------------------------------- rafraichis.
    def refresh_header(self):
        sm = self.state_mgr
        d = sm.data
        used, quota = sm.total_used(), sm.quota_bytes()
        pct = used / float(quota)
        self.lbl_used.configure(text=fmt_bytes(used))
        hors = sm.off_used()
        txt = "sur %d Mo  -  %.0f %% de l'enveloppe" % (d["quota_mb"], 100 * pct)
        if not d["engaged"]:
            txt += "   (protection inactive : rien n'est decompte)"
        elif hors:
            txt += "   -  %s observes hors protection" % fmt_bytes(hors)
        self.lbl_quota.configure(text=txt)
        col = C_OK if pct < 0.5 else (C_WARN if pct < 0.9 else C_DANGER)
        self.bar.delete("all")
        w = max(1, self.bar.winfo_width())
        self.bar.create_rectangle(0, 2, w, 12, fill=C_PANEL2, outline="")
        self.bar.create_rectangle(0, 2, int(w * min(1.0, pct)), 12, fill=col, outline="")
        rem = sm.next_reset()
        hh, rr = divmod(int(rem.total_seconds()), 3600)
        mm, ss = divmod(rr, 60)
        self.lbl_reset.configure(text="Remise a zero dans %02d h %02d min %02d s "
                                      "(a %02d:%02d, heure %s)"
                                      % (hh, mm, ss, d["reset_hh"], d["reset_mm"],
                                         "UTC" if d["tz_mode"] == "utc" else "du PC"))
        live = sum(self.rates.values())
        if live > 1024:
            gros = max(self.rates.items(), key=lambda kv: kv[1])
            self.lbl_debit.configure(
                text="%s/s en ce moment  -  surtout %s"
                     % (fmt_bytes(live), self.label_for(gros[0])),
                fg=C_WARN if live > 200 * 1024 else C_ACCENT)
        else:
            self.lbl_debit.configure(text="Trafic au repos", fg=C_TXT_DIM)
        suite = sm.schedule_next_change()
        if d.get("schedule_enabled"):
            if sm.schedule_open():
                self.lbl_reset.configure(
                    text=self.lbl_reset.cget("text") +
                         ("   |   plage ouverte jusqu'a %s" % suite[1] if suite else ""))
            else:
                self.lbl_reset.configure(
                    text="INTERNET COUPE (hors plage horaire)" +
                         ("   -   reouverture a %s" % suite[1] if suite else ""))
        if d["engaged"]:
            if sm.profile.get("allow_all"):
                self.lbl_shield.configure(text="PROTECTION ACTIVE - profil Libre",
                                          fg=C_WARN)
            else:
                self.lbl_shield.configure(text="PROTECTION ACTIVE", fg=C_OK)
            self.btn_engage.configure(text="Desactiver la protection",
                                      bg=C_PANEL2, fg=C_TXT)
        else:
            self.lbl_shield.configure(text="PROTECTION INACTIVE", fg=C_WARN)
            self.btn_engage.configure(text="Activer la protection",
                                      bg=C_ACCENT, fg="#06101d")
        self.lbl_engine.configure(
            text="comptage %s" % ("detaille par application"
                                  if self.meter.mode == "etw" else "global estime"))

    def refresh_profiles(self):
        sm = self.state_mgr
        if len(self.profile_cards) != (len(sm.data["profiles"]) if sm.multi_profiles() else 0):
            self.rebuild_profile_cards()
        per = sm.data["usage"]["per_profile"]
        for pid, card in self.profile_cards.items():
            prof = sm.data["profiles"].get(pid)
            if not prof:
                continue
            active = (pid == sm.data["active_profile"])
            bg = C_PANEL2 if active else C_PANEL
            card["frame"].configure(bg=bg, highlightbackground=prof["color"] if active else C_PANEL,
                                    highlightcolor=prof["color"] if active else C_PANEL)
            for k in ("name", "stat"):
                card[k].configure(bg=bg)
            n_allow = sum(1 for v in prof["apps"].values() if v)
            conso = per.get(pid, 0)
            if prof.get("allow_all"):
                txt = "tout autorise  -  %s" % fmt_bytes(conso)
            else:
                txt = "%d app. autorisees  -  %s" % (n_allow, fmt_bytes(conso))
            card["stat"].configure(text=txt,
                                   fg=prof["color"] if active else C_TXT_DIM)

    def sort_apps(self, key):
        """Clic sur un en-tete : trie la liste. Deuxieme clic sur la meme
        colonne : inverse l'ordre."""
        if self.sort_key == key:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_key = key
            self.sort_desc = (key == "conso")
        self.refresh_apps()

    def refresh_apps(self):
        sm = self.state_mgr
        per_app = sm.data["usage"]["per_app"]
        self.lbl_apps.configure(
            text="Applications  -  %s%s" % (sm.profile_name(),
                                            "" if not sm.multi_profiles() else ""))
        sel = self.tv_apps.selection()
        selval = self.tv_apps.item(sel[0], "values")[3] if sel else None
        self.tv_apps.delete(*self.tv_apps.get_children())

        entries = dict(sm.profile["apps"])
        for it in self.pending:
            entries.setdefault(it["path"].lower(), None)

        def conso_of(path):
            u = per_app.get(path, {})
            return u.get("sent", 0) + u.get("recv", 0)

        def key_of(kv):
            path, allowed = kv
            if self.sort_key == "conso":
                return conso_of(path)
            if self.sort_key == "acces":
                # en attente, puis autorises, puis bloques
                return ({None: 0, True: 1, False: 2}[allowed], -conso_of(path))
            if self.sort_key == "path":
                return path
            return self.label_for(path).lower()

        rows = sorted(entries.items(), key=key_of, reverse=self.sort_desc)

        # rappel visuel de la colonne de tri
        libelles = {"app": "Application", "acces": "Acces", "conso": "Consomme",
                    "path": "Emplacement"}
        fleche = " v" if self.sort_desc else " ^"
        for c, t in libelles.items():
            self.tv_apps.heading(c, text=t + (fleche if c == self.sort_key else ""))

        for path, allowed in rows:
            conso = conso_of(path)
            name = self.label_for(path)
            if allowed is None:
                etat, tag = "en attente", "wait"
            elif allowed:
                etat, tag = "autorise", "allow"
            else:
                etat, tag = "bloque", "block"
            self.tv_apps.insert("", "end", tags=(tag,),
                                values=(name, etat, fmt_bytes(conso), path))
        if selval:
            for iid in self.tv_apps.get_children():
                if self.tv_apps.item(iid, "values")[3] == selval:
                    self.tv_apps.selection_set(iid)
                    break

    def refresh_pending_label(self):
        n = len(self.pending)
        self.lbl_pending.configure(text=("%d demande(s) en attente" % n) if n else "")

    def refresh_all(self):
        self.refresh_header()
        self.refresh_profiles()
        self.refresh_apps()
        self.refresh_pending_label()

    # ------------------------------------------------------------ boucles
    def _loop_fast(self):
        new = False
        while True:
            try:
                item = self.pending_q.get_nowait()
            except queue.Empty:
                break
            self.pending.append(item)
            new = True
        if new:
            self.refresh_pending_label()
            self.refresh_apps()
        if self.toast is None and self.pending and self.state_mgr.data["notify_enabled"]:
            self._show_next_toast()
        self.after(500, self._loop_fast)

    def _loop_slow(self):
        sm = self.state_mgr
        if sm.roll_period_if_needed():
            self.status("Nouvelle journee - compteurs remis a zero")
            self.tray.notify(APP_NAME, "Nouvelle enveloppe : %d Mo disponibles."
                             % sm.data["quota_mb"])
        acc = self.meter.drain()
        now = time.time()
        dt = max(0.5, now - self._last_tick)
        self._last_tick = now
        tick = {}
        if acc:
            for pid, (s, r) in acc.items():
                if pid == 0:
                    path = "(ensemble du systeme)"
                else:
                    path = (self.scanner.exe_for(pid) if psutil else None) or "(pid %s)" % pid
                sm.add_usage(path, s, r, label=self.label_for(path),
                             compte=bool(sm.data["engaged"]))
                tick[path.lower()] = tick.get(path.lower(), 0) + s + r
        self.rates = {p: v / dt for p, v in tick.items()}
        ouvert = sm.schedule_open()
        if ouvert != self._slot_state:
            if self._slot_state is not None:
                suite = sm.schedule_next_change()
                if ouvert:
                    msg = "Plage horaire ouverte : Internet retabli"
                else:
                    msg = "Plage horaire fermee : Internet coupe"
                if suite:
                    msg += " jusqu'a %s" % suite[1]
                self.status(msg)
                self.tray.notify(APP_NAME, msg)
                log_line(msg)
            self._slot_state = ouvert
            if sm.data["engaged"]:
                self.apply_firewall()

        self.check_alerts()
        if self.state().lower() != "withdrawn":
            self.refresh_all()
        self.refresh_window_icon()
        self.tray.refresh()
        sm.save()
        self.after(2000, self._loop_slow)

    def check_alerts(self):
        sm = self.state_mgr
        pct = 100.0 * sm.total_used() / sm.quota_bytes()
        for seuil in sorted(sm.data["alert_pct"]):
            if pct >= seuil and seuil not in sm.data["alerts_fired"]:
                sm.data["alerts_fired"].append(seuil)
                msg = ("%d %% de l'enveloppe consommes (%s sur %d Mo). "
                       "Rien n'est coupe." % (seuil, fmt_bytes(sm.total_used()),
                                              sm.data["quota_mb"]))
                self.tray.notify(APP_NAME, msg)
                if self.state().lower() != "withdrawn":
                    messagebox.showwarning("Enveloppe Internet", msg)

    def _startup_checks(self):
        missing = []
        if psutil is None:
            missing.append("psutil")
        if _etw is None:
            missing.append("pywintrace")
        if pystray is None or Image is None:
            missing.append("pystray pillow")
        if missing:
            messagebox.showwarning(
                "Modules a installer",
                "Il manque : %s\n\nOuvre l'invite de commandes et tape :\n"
                "    pip install %s\n\n"
                "Sans psutil : aucune detection des programmes.\n"
                "Sans pywintrace : comptage global au lieu du detail par application.\n"
                "Sans pystray/pillow : pas d'icone dans la zone de notification."
                % (", ".join(missing), " ".join(missing)))
        if getattr(self, "_roll_au_demarrage", False):
            hier = sorted(self.state_mgr.data["history"].keys())[-1:] or [""]
            veille = self.state_mgr.data["history"].get(hier[0], {})
            volume = veille.get("total", 0) if isinstance(veille, dict) else 0
            msg = ("Nouvelle periode : compteur remis a zero, %d Mo disponibles"
                   % self.state_mgr.data["quota_mb"])
            if volume:
                msg += "  (periode precedente : %s)" % fmt_bytes(volume)
            self.status(msg)
            log_line(msg)
        if self.state_mgr.data.get("engaged"):
            self.apply_firewall(full=True)
        self.refresh_all()


# ==========================================================================
#  DEMARRAGE
# ==========================================================================

def main():
    if os.name != "nt":
        print("NetGate fonctionne uniquement sous Windows.")
        return 1

    log_line("--- demarrage %s | python %s | admin=%s | psutil=%s | pywintrace=%s | "
             "pystray=%s | pillow=%s"
             % (VERSION_TXT, sys.version.split()[0], is_admin(), psutil is not None,
                _etw is not None, pystray is not None, Image is not None))

    if not is_admin():
        root = tk.Tk()
        root.withdraw()
        go = messagebox.askyesno(
            APP_NAME,
            "NetGate a besoin des droits administrateur pour piloter le pare-feu "
            "Windows.\n\nOUI : relancer en administrateur.\n"
            "NON : ouvrir quand meme en mode limite (l'interface et les compteurs "
            "fonctionnent, le blocage non).")
        root.destroy()
        if go:
            try:
                relaunch_as_admin()
            except Exception:
                log_error("elevation impossible")
                print("Elevation impossible, detail dans", LOG_FILE)
            return 0
        log_line("mode limite : sans droits administrateur")

    app = None
    try:
        app = NetGateApp()
    except Exception as e:
        log_error("plantage pendant la construction de la fenetre")
        _fatal(e)
        return 1
    try:
        app.mainloop()
    except Exception as e:
        log_error("plantage pendant l'execution")
        _fatal(e)
        return 1
    return 0


def _fatal(e):
    """Montre l'erreur au lieu de laisser la console se refermer."""
    detail = traceback.format_exc()
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            APP_NAME,
            "NetGate n'a pas pu demarrer.\n\n%s : %s\n\n"
            "Le detail complet est dans :\n%s\n\n"
            "Si le probleme persiste, renomme netgate.state.json dans ce dossier "
            "pour "
            "repartir d'une configuration neuve."
            % (type(e).__name__, e, LOG_FILE))
        root.destroy()
    except Exception:
        pass
    print(detail)
    print("Detail enregistre dans :", LOG_FILE)
    try:
        input("Appuie sur Entree pour fermer...")
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
