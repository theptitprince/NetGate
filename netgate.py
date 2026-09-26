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
application. NetGate compte ce que chacune consomme, te previent quand
l'enveloppe du jour s'epuise et coupe Internet quand elle est vide.

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
V1.4  Coupure reelle a 100 % de l'enveloppe (case dans les reglages) avec
      rallonge du jour. Coupures et blocages passent par des regles de
      blocage, qui l'emportent sur les regles d'autorisation que Windows et
      les logiciels installes ont deja posees. Enveloppe mesuree sur la carte
      reseau physique ; localhost, reseau local et tunnels VPN ne sont plus
      decomptes. Un programme mis a jour (dossier portant un numero de
      version) garde sa decision au lieu de reapparaitre en double.
"""

import ctypes
import glob
import hashlib
import ipaddress
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
VERSION = "1.4"

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
# Nom fixe : apres un arret brutal, la session ETW restee ouverte est reprise
# au lieu d'en ouvrir une nouvelle a chaque lancement.
ETW_SESSION = "NetGate-Reseau"

# Adresses publiques, c'est-a-dire tout sauf localhost, reseaux prives,
# liaison locale et multidiffusion. Les regles de blocage ne visent qu'elles :
# couper Internet ne coupe ni les serveurs locaux ni le reseau de la maison.
# 64:ff9b:: : Internet IPv4 vu depuis un reseau mobile tout IPv6 (NAT64).
INTERNET_IPS = ("1.0.0.0-9.255.255.255,11.0.0.0-126.255.255.255,"
                "128.0.0.0-169.253.255.255,169.255.0.0-172.15.255.255,"
                "172.32.0.0-192.167.255.255,192.169.0.0-223.255.255.255,"
                "2000::/3,64:ff9b::/96,64:ff9b:1::/48")

# Cle regroupant le trafic dont le programme n'a pas pu etre identifie
# (processus deja termine au moment du releve).
UNATTRIBUTED = "(non attribue)"

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


def empty_usage(period=""):
    """Compteurs d'une periode. total_* entame l'enveloppe, off_* est mesure
    hors protection, bonus est la rallonge accordee pour la periode, local
    le trafic localhost et reseau local ecarte du compte."""
    return {"period": period, "per_app": {}, "per_profile": {}, "per_hour": {},
            "total_sent": 0, "total_recv": 0, "off_sent": 0, "off_recv": 0,
            "bonus": 0, "local": 0}


DEFAULT_STATE = {
    "schema": 3,
    "quota_mb": 500,
    "quota_cut": True,             # couper Internet a 100 % de l'enveloppe
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
    "nic_exclude": [],             # cartes physiques que l'utilisateur ne compte pas
    "nic_include": [],             # cartes virtuelles qu'il compte quand meme
    "active_profile": "defaut",
    "profiles": DEFAULT_PROFILES,
    "catalog": {},
    "usage": empty_usage(),
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


def rule_name_for(path, kind="OUT"):
    """OUT : autorisation du programme ; BLK : blocage vers Internet."""
    h = hashlib.sha1(path.lower().encode("utf-8", "ignore")).hexdigest()[:14]
    return RULE_PREFIX + kind + "_" + h


# Dossiers qui changent de nom a chaque mise a jour :
#   152.0.4191.66, 4.18.26080.3-0, app-1.0.9187, jre1.8.0_381 ...
_RE_DOSSIER_VERSION = re.compile(r"^([a-z]{0,4}-?)\d+(?:\.\d+){1,4}(?:[-_+][0-9a-z]+)*$")
#   paquets du Store : claude_2.110.0.0_x64__pzs8sxrjxfjjc
_RE_DOSSIER_PAQUET = re.compile(r"^(.+?)_\d+(?:\.\d+){1,3}_([a-z0-9]+)_([^_]*)_([a-z0-9]{13})$")
#   pilotes : lenovofnandfunctionkeys.inf_amd64_5e21bf389d23855a
_RE_DOSSIER_PILOTE = re.compile(r"^(.+\.inf)_([a-z0-9]+)_[0-9a-f]{16}$")


def app_key(path):
    """Identite stable d'un programme : le chemin en minuscules, ou les
    dossiers portant un numero de version sont remplaces par '*'. Ainsi une
    mise a jour (claude_2.110 -> claude_2.111) garde la meme ligne et la
    meme decision au lieu d'apparaitre en double. La cle reste un motif glob
    valide pour retrouver les versions installees."""
    p = (path or "").strip().lower()
    if not p or p.startswith("(") or "\\" not in p:
        return p
    parts = p.split("\\")
    for i in range(1, len(parts) - 1):          # ni le lecteur, ni le .exe
        seg = parts[i]
        m = _RE_DOSSIER_PAQUET.match(seg)
        if m:
            parts[i] = "%s_*_%s_%s_%s" % m.groups()
            continue
        m = _RE_DOSSIER_PILOTE.match(seg)
        if m:
            parts[i] = "%s_%s_*" % m.groups()
            continue
        m = _RE_DOSSIER_VERSION.match(seg)
        if m:
            parts[i] = m.group(1) + "*"
    return "\\".join(parts)


_NETS_LOCAUX = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/3",            # multidiffusion, reserve, diffusion
    "::/128", "::1/128", "fe80::/10", "fc00::/7", "ff00::/8")]


def addr_scope(ip, own=frozenset(), prefixes=frozenset()):
    """'self' : cette machine (localhost ou une de ses propres adresses) ;
    'lan' : reseau local (prive, liaison locale, multidiffusion, ou meme
    prefixe IPv6 /64 qu'une adresse de la machine) ; 'internet' : le reste.
    Une adresse illisible compte comme Internet : mieux vaut decompter un
    octet de trop qu'en oublier un."""
    try:
        a = ipaddress.ip_address(str(ip).split("%")[0].strip())
    except ValueError:
        return "internet"
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if a.is_loopback or str(a) in own:
        return "self"
    if any(a in n for n in _NETS_LOCAUX if n.version == a.version):
        return "lan"
    if a.version == 6 and (int(a) >> 64) in prefixes:
        return "lan"
    return "internet"


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
    CUT_NAME = RULE_PREFIX + "CUT"
    _echec_signale = False

    # ------------------------------------------------- fabrication des lignes
    @staticmethod
    def line_allow(path, label=""):
        name = rule_name_for(path)
        return ['advfirewall firewall delete rule name=%s' % name,
                'advfirewall firewall add rule name=%s dir=out action=allow '
                'program="%s" enable=yes profile=any description="NetGate %s"'
                % (name, path, (label or os.path.basename(path))[:60])]

    @staticmethod
    def line_block(path, label=""):
        """Bloque le programme vers Internet. Dans le pare-feu Windows, une
        regle de blocage l'emporte sur toutes les regles d'autorisation, y
        compris celles que Windows ou l'installateur du logiciel ont posees
        de leur cote : sans elle, "Bloquer" ne suffit pas pour ces
        programmes-la. Localhost et reseau local restent ouverts."""
        name = rule_name_for(path, "BLK")
        return ['advfirewall firewall delete rule name=%s' % name,
                'advfirewall firewall add rule name=%s dir=out action=block '
                'program="%s" remoteip=%s enable=yes profile=any '
                'description="NetGate bloque %s"'
                % (name, path, INTERNET_IPS, (label or os.path.basename(path))[:60])]

    @staticmethod
    def line_delete(path, kinds=("OUT", "BLK")):
        return ['advfirewall firewall delete rule name=%s' % rule_name_for(path, k)
                for k in kinds]

    @staticmethod
    def lines_cut(enable):
        """Coupure generale (enveloppe epuisee, hors plage horaire) : une seule
        regle de blocage vers toutes les adresses publiques. Elle passe devant
        toutes les autorisations, celles de NetGate comme celles deja posees
        dans Windows ; localhost et reseau local restent ouverts."""
        lines = ['advfirewall firewall delete rule name=%s' % Firewall.CUT_NAME]
        if enable:
            lines.append('advfirewall firewall add rule name=%s dir=out action=block '
                         'remoteip=%s enable=yes profile=any '
                         'description="NetGate : Internet coupe"'
                         % (Firewall.CUT_NAME, INTERNET_IPS))
        return lines

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
        """Execute toutes les commandes en un seul processus netsh.

        netsh -f execute toutes les lignes meme si l'une echoue, et renvoie 1
        des qu'une ligne echoue : c'est le cas normal d'une suppression de
        regle absente. Un code 1 ne justifie donc pas de rejouer le script."""
        lines = [l for l in lines if l]
        if not lines:
            return True
        # netsh lit ses scripts dans l'encodage local de la machine : une
        # ligne qui ne s'y ecrit pas (chemin en cyrillique, par exemple) est
        # executee a part, en argument Unicode.
        script, a_part = [], []
        for l in lines:
            try:
                l.encode("mbcs")
                script.append(l)
            except (UnicodeEncodeError, LookupError):
                a_part.append(l)
        ok = True
        if script:
            fichier = os.path.join(tempfile.gettempdir(), "netgate_%d_%d.netsh"
                                   % (os.getpid(), int(time.time() * 1000)))
            try:
                with open(fichier, "w", encoding="mbcs") as f:
                    f.write("\n".join(script) + "\n")
                rc, out = run_netsh(["-f", fichier], timeout=120)
                if rc != 0 and not Firewall._echec_signale:
                    Firewall._echec_signale = True
                    log_line("netsh -f : au moins une ligne a echoue (normal pour la "
                             "suppression d'une regle absente) :\n" + out[:600])
            except Exception:
                log_error("script netsh")
                ok = Firewall._run_one_by_one(script)
            finally:
                try:
                    os.remove(fichier)
                except Exception:
                    pass
        if a_part:
            ok = Firewall._run_one_by_one(a_part) and ok
        return ok

    @staticmethod
    def _run_one_by_one(lines):
        """Une commande par processus netsh, pour les lignes que le script ne
        peut pas porter. Les valeurs entre guillemets (chemins avec espaces)
        doivent rester solidaires de leur mot-cle."""
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
    def panic_restore(paths):
        """Politique sortante d'origine, coupure levee, et plus aucune regle
        NETGATE_ pour les programmes connus."""
        lines = list(Firewall.line_lockdown(False))
        lines += Firewall.lines_cut(False)
        for p in paths:
            lines += Firewall.line_delete(p)
        lines += Firewall.lines_essentials(False)
        return Firewall.run_script(lines)


# ==========================================================================
#  COMPTEUR ETW
# ==========================================================================

class EtwMeter(threading.Thread):
    """Attribue a chaque processus les octets qu'il echange avec Internet.

    Chaque evenement du fournisseur Kernel-Network porte les deux adresses de
    la connexion. Le trafic de la machine avec elle-meme (localhost : WAMP,
    MySQL, PHP...) et avec le reseau local ne consomme pas le forfait : il
    est mis de cote au lieu d'etre impute aux programmes."""
    daemon = True

    def __init__(self):
        super().__init__(name="EtwMeter")
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._reset_acc()
        self.mode = "init"
        self.error = ""
        self._job = None
        self._scopes = {}
        self.own = frozenset(("127.0.0.1", "::1"))
        self.counted = frozenset()
        self.prefixes = frozenset()

    def _reset_acc(self):
        self._acc = {}              # pid -> [envoye, recu] avec Internet
        self._inet = [0, 0]         # tout le trafic Internet, toutes cartes
        self._lan = [0, 0]          # reseau local passe par une carte decomptee
        self._local = 0             # localhost + reseau local, pour information

    def set_addresses(self, own, counted, prefixes):
        """Adresses de la machine, adresses des cartes decomptees, prefixes
        IPv6 /64 de la machine. Mis a jour depuis l'interface."""
        self.own, self.counted, self.prefixes = own, counted, prefixes
        self._scopes = {}

    def drain(self):
        with self._lock:
            out = {"apps": self._acc, "inet": self._inet, "lan": self._lan,
                   "local": self._local}
            self._reset_acc()
        return out

    def stop(self):
        self._stop.set()

    def _scope(self, ip):
        """(portee, adresse normalisee), avec cache : le rappel ETW tourne a
        chaque paquet."""
        r = self._scopes.get(ip)
        if r is None:
            try:
                canon = str(ipaddress.ip_address(str(ip).split("%")[0].strip()))
            except ValueError:
                canon = str(ip)
            r = (addr_scope(ip, self.own, self.prefixes), canon)
            if len(self._scopes) > 5000:
                self._scopes = {}
            self._scopes[ip] = r
        return r

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
        sens = 0 if event_id in ETW_SENT_IDS else 1
        if sens == 1 and event_id not in ETW_RECV_IDS:
            return
        pid = self._pick(payload, ("PID", "pid", "ProcessId"))
        size = self._pick(payload, ("size", "Size", "TransferSize", "DataLength"))
        if pid is None or not size or size <= 0:
            return
        a, b = payload.get("saddr"), payload.get("daddr")
        sa, ca = self._scope(a) if a else ("internet", "")
        sb, cb = self._scope(b) if b else ("internet", "")
        with self._lock:
            if sa == "internet" or sb == "internet":
                slot = self._acc.setdefault(pid, [0, 0])
                slot[sens] += size
                self._inet[sens] += size
                return
            self._local += size
            # reseau local passe par une carte decomptee : la carte l'a vu
            # passer, il faudra le retirer de son compteur
            if sa != sb and (ca if sa == "self" else cb) in self.counted:
                self._lan[sens] += size

    def run(self):
        if _etw is None or _GUID is None:
            self.mode, self.error = "off", "pywintrace absent"
            return
        try:
            providers = [_etw.ProviderInfo("Microsoft-Windows-Kernel-Network",
                                           _GUID(KERNEL_NETWORK_GUID))]
            try:
                # les evenements hors envoi/reception ne sont meme pas decodes
                self._job = _etw.ETW(session_name=ETW_SESSION, providers=providers,
                                     event_callback=self._callback,
                                     event_id_filters=sorted(ETW_SENT_IDS | ETW_RECV_IDS))
            except TypeError:       # pywintrace trop ancien pour ces options
                self._job = _etw.ETW(providers=providers, event_callback=self._callback)
            self._job.start()
            self.mode = "etw"
        except Exception as e:
            self.mode, self.error = "off", str(e)
            log_line("comptage par programme indisponible : %s" % e)
            return
        self._stop.wait()
        try:
            self._job.stop()
        except Exception:
            pass


# ==========================================================================
#  COMPTEUR DES CARTES RESEAU
# ==========================================================================

class _GuidStruct(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

    def __str__(self):
        d4 = bytes(self.Data4)
        return "{%08X-%04X-%04X-%s-%s}" % (self.Data1, self.Data2, self.Data3,
                                           d4[:2].hex().upper(), d4[2:].hex().upper())


class _MibIfRow2(ctypes.Structure):
    """MIB_IF_ROW2 (netioapi.h), 1352 octets en 64 bits."""
    _fields_ = [
        ("InterfaceLuid", ctypes.c_uint64), ("InterfaceIndex", ctypes.c_ulong),
        ("InterfaceGuid", _GuidStruct),
        ("Alias", ctypes.c_wchar * 257), ("Description", ctypes.c_wchar * 257),
        ("PhysicalAddressLength", ctypes.c_ulong),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
        ("Mtu", ctypes.c_ulong), ("Type", ctypes.c_ulong),
        ("TunnelType", ctypes.c_int), ("MediaType", ctypes.c_int),
        ("PhysicalMediumType", ctypes.c_int), ("AccessType", ctypes.c_int),
        ("DirectionType", ctypes.c_int),
        ("Flags", ctypes.c_ubyte),     # bit 0 : materielle, bit 1 : filtre
        ("OperStatus", ctypes.c_int), ("AdminStatus", ctypes.c_int),
        ("MediaConnectState", ctypes.c_int), ("NetworkGuid", _GuidStruct),
        ("ConnectionType", ctypes.c_int),
        ("TransmitLinkSpeed", ctypes.c_uint64), ("ReceiveLinkSpeed", ctypes.c_uint64),
        ("InOctets", ctypes.c_uint64), ("InUcastPkts", ctypes.c_uint64),
        ("InNUcastPkts", ctypes.c_uint64), ("InDiscards", ctypes.c_uint64),
        ("InErrors", ctypes.c_uint64), ("InUnknownProtos", ctypes.c_uint64),
        ("InUcastOctets", ctypes.c_uint64), ("InMulticastOctets", ctypes.c_uint64),
        ("InBroadcastOctets", ctypes.c_uint64), ("OutOctets", ctypes.c_uint64),
        ("OutUcastPkts", ctypes.c_uint64), ("OutNUcastPkts", ctypes.c_uint64),
        ("OutDiscards", ctypes.c_uint64), ("OutErrors", ctypes.c_uint64),
        ("OutUcastOctets", ctypes.c_uint64), ("OutMulticastOctets", ctypes.c_uint64),
        ("OutBroadcastOctets", ctypes.c_uint64), ("OutQLen", ctypes.c_uint64),
    ]


class NicMeter:
    """Compteurs d'octets des cartes reseau, ceux du Gestionnaire des taches.

    C'est la mesure la plus proche de celle de l'operateur : tout ce qui
    passe par la carte, en-tetes compris, trafic des machines virtuelles
    compris, et rien de ce qui reste dans la machine (localhost). Seules les
    cartes physiques comptent par defaut : une carte virtuelle (tunnel VPN,
    VirtualBox, Hyper-V) ne fait que relayer un trafic qui sort ensuite par
    la carte physique, la compter le decompterait deux fois."""

    MEDIUMS_PHYSIQUES = (8, 10, 12)     # cle 4G (WWAN), Bluetooth, WiMax

    def __init__(self):
        self._base = {}
        self.ifaces = []                # dernier releve, pour les reglages
        self._signale = False
        try:
            self._dll = ctypes.WinDLL("iphlpapi")
            self._dll.GetIfTable2.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
            self._dll.GetIfTable2.restype = ctypes.c_ulong
            self._dll.FreeMibTable.argtypes = [ctypes.c_void_p]
            self._dll.FreeMibTable.restype = None
        except Exception:
            self._dll = None

    @property
    def available(self):
        return self._dll is not None

    def read(self):
        ptr = ctypes.c_void_p()
        rc = self._dll.GetIfTable2(ctypes.byref(ptr))
        if rc != 0 or not ptr.value:
            raise OSError("GetIfTable2 a renvoye %s" % rc)
        try:
            n = ctypes.c_ulong.from_address(ptr.value).value
            rows = (_MibIfRow2 * n).from_address(ptr.value + ctypes.sizeof(ctypes.c_uint64))
            out = []
            for r in rows:
                # les "filtres" (QoS, WFP, Npcap...) recopient les compteurs
                # de la carte qu'ils surveillent ; 24 = boucle locale
                if r.Flags & 2 or r.Type == 24:
                    continue
                out.append({"guid": str(r.InterfaceGuid), "alias": r.Alias,
                            "desc": r.Description, "up": r.OperStatus == 1,
                            "physique": bool(r.Flags & 1)
                            or r.PhysicalMediumType in self.MEDIUMS_PHYSIQUES
                            or r.Type in (243, 244),
                            "tx": r.OutOctets, "rx": r.InOctets})
            return out
        finally:
            self._dll.FreeMibTable(ptr)

    def poll(self, compte):
        """(envoye, recu) depuis le releve precedent sur les cartes pour
        lesquelles compte(carte) est vrai, ou None si la lecture echoue. Une
        carte vue pour la premiere fois sert de point de depart."""
        if not self._dll:
            return None
        try:
            rows = self.read()
        except Exception as e:
            if not self._signale:
                self._signale = True
                log_line("lecture des cartes reseau impossible : %s" % e)
            return None
        self.ifaces = rows
        ds = dr = 0
        base = {}
        for it in rows:
            cur = (it["tx"], it["rx"])
            prev = self._base.get(it["guid"])
            base[it["guid"]] = cur
            if prev is None or not compte(it):
                continue
            # compteur reparti de zero (carte desactivee puis reactivee)
            ds += cur[0] - prev[0] if cur[0] >= prev[0] else cur[0]
            dr += cur[1] - prev[1] if cur[1] >= prev[1] else cur[1]
        self._base = base
        return ds, dr


# ==========================================================================
#  DETECTION DES TENTATIVES
# ==========================================================================

class ConnScanner(threading.Thread):
    """Signale a l'interface chaque executable qui ouvre une connexion vers
    Internet ("conn"), et chaque executable lance depuis un nouveau dossier
    de version d'un programme deja tranche ("proc") : apres une mise a jour,
    la decision doit suivre sans reposer la question. Le tri entre demande
    et simple mise a jour se fait dans l'interface."""
    daemon = True

    def __init__(self, out_queue, interval=1.5):
        super().__init__(name="ConnScanner")
        self._stop = threading.Event()
        self.q = out_queue
        self.interval = interval
        self.pid_cache = {}
        self.reported = set()       # chemins deja signales
        self.watch = frozenset()    # identites tranchees (app_key), tenues a jour par l'interface
        self._tour = 0
        self._signale = False

    def stop(self):
        self._stop.set()

    def forget(self, key):
        self.reported = {p for p in self.reported if app_key(p) != key}

    def reset_asked(self):
        self.reported = set()

    def exe_for(self, pid):
        """Chemin de l'executable. Le cache est verifie par l'heure de
        creation : Windows recycle vite les numeros de processus, et un
        numero reattribue ne doit pas heriter du nom de l'ancien."""
        if pid in (0, 4):
            return "System"
        ent = self.pid_cache.get(pid)
        try:
            proc = psutil.Process(pid)
        except Exception:
            return ent[0] if ent else None   # termine depuis : le nom connu vaut
        try:
            ct = proc.create_time()
        except Exception:
            ct = None
        if ent and (ct is None or ent[1] is None or ent[1] == ct):
            return ent[0]
        try:
            exe = proc.exe() or None
        except Exception:
            exe = None
        if not exe:
            try:
                nom = proc.name()
            except Exception:
                nom = None
            if nom:
                # sans droits administrateur, un service (svchost...) ne livre
                # que son nom : son chemin est presque toujours System32
                sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                     "System32", nom)
                exe = sys32 if os.path.isfile(sys32) else nom
        if exe:
            self.pid_cache[pid] = (exe, ct)
        return exe

    def _report(self, exe, pid, src):
        path = exe.lower()
        if path in self.reported:
            return
        self.reported.add(path)
        self.q.put({"path": exe, "pid": pid, "ts": time.time(), "src": src})

    def _scan_connections(self):
        pids = set()
        for c in psutil.net_connections(kind="inet"):
            if not c.pid or c.status == "LISTEN":
                continue
            if c.raddr:
                # localhost (WAMP, MySQL...) et reseau local ne consomment
                # pas le forfait : pas de demande pour eux
                if addr_scope(c.raddr[0]) != "internet":
                    continue
            elif c.laddr and addr_scope(c.laddr[0]) == "self":
                continue
            pids.add(c.pid)
        for pid in pids:
            exe = self.exe_for(pid)
            if exe:
                self._report(exe, pid, "conn")

    def _scan_processes(self):
        watch = self.watch
        if not watch:
            return
        for p in psutil.process_iter(["pid", "exe"]):
            exe = p.info.get("exe")
            if exe and exe.lower() not in self.reported and app_key(exe) in watch:
                self._report(exe, p.info["pid"], "proc")

    def run(self):
        if psutil is None:
            return
        while not self._stop.is_set():
            try:
                self._scan_connections()
                self._tour += 1
                if self._tour % 5 == 0:
                    self._scan_processes()
            except Exception:
                if not self._signale:
                    self._signale = True
                    log_error("detection des connexions")
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
        schema = disk.get("schema", 1) if disk else DEFAULT_STATE["schema"]
        if not self.data.get("profiles"):
            self.data["profiles"] = json.loads(json.dumps(DEFAULT_PROFILES))
        if not isinstance(self.data.get("usage"), dict):
            self.data["usage"] = empty_usage()
        for k, v in empty_usage().items():
            self.data["usage"].setdefault(k, v)
        for k in ("nic_exclude", "nic_include"):
            if not isinstance(self.data.get(k), list):
                self.data[k] = []

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

        if schema < 3:
            if disk:
                try:
                    with open(STATE_FILE + ".v2.bak", "w", encoding="utf-8") as f:
                        json.dump(disk, f, indent=2, ensure_ascii=False)
                except Exception:
                    pass
            self._migrate_v3()

    def _migrate_v3(self):
        """Schema 3 : decisions, catalogue et compteurs sont ranges par
        identite de programme (app_key) et non plus par chemin exact. Les
        versions successives d'un meme programme fusionnent en une ligne ;
        leurs chemins restent dans le catalogue pour les regles du pare-feu.
        Les seaux "(pid N)" se fondent en un seul "(non attribue)"."""
        d = self.data
        ancien = d.get("catalog", {}) or {}
        cat = {}

        def entree(key, path=None, info=None):
            e = cat.setdefault(key, {"name": os.path.basename(key) or key,
                                     "first_seen": time.time(), "paths": []})
            if info:
                e["first_seen"] = min(e["first_seen"],
                                      info.get("first_seen", e["first_seen"]))
                e["lifetime"] = e.get("lifetime", 0) + info.get("lifetime", 0)
                if info.get("label"):
                    e["label"] = info["label"]
            if path and path not in e["paths"]:
                e["paths"].append(path)

        # du plus ancien au plus recent : les chemins suivent l'ordre des versions
        for path, info in sorted(ancien.items(),
                                 key=lambda kv: kv[1].get("first_seen", 0)):
            if not path.startswith("("):
                entree(app_key(path), path, info)

        fusions = 0
        for prof in d["profiles"].values():
            apps, vu = {}, {}
            for path, allow in prof.get("apps", {}).items():
                key = app_key(path)
                entree(key, path)
                ts = ancien.get(path, {}).get("first_seen", 0)
                if key in apps:
                    fusions += 1
                # deux versions tranchees differemment : la plus recente l'emporte
                if key not in apps or ts >= vu[key]:
                    apps[key], vu[key] = bool(allow), ts
            prof["apps"] = apps
        d["catalog"] = cat

        def cle(k):
            return UNATTRIBUTED if k.startswith("(") else app_key(k)

        per_app = {}
        for k, v in d["usage"].get("per_app", {}).items():
            c = cle(k)
            slot = per_app.setdefault(c, {"sent": 0, "recv": 0,
                                          "name": os.path.basename(c) or c})
            slot["sent"] += v.get("sent", 0)
            slot["recv"] += v.get("recv", 0)
        d["usage"]["per_app"] = per_app
        for jour in (d.get("history") or {}).values():
            if isinstance(jour, dict) and isinstance(jour.get("per_app"), dict):
                fusion = {}
                for k, v in jour["per_app"].items():
                    fusion[cle(k)] = fusion.get(cle(k), 0) + (v or 0)
                jour["per_app"] = fusion
        d["schema"] = 3
        log_line("migration v3 : %d chemins ranges sous %d programmes, %d doublons "
                 "de version fusionnes dans les listes"
                 % (sum(1 for p in ancien if not p.startswith("(")), len(cat), fusions))

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

    # -- programmes --------------------------------------------------------
    # Les decisions sont rangees par identite (app_key) ; le pare-feu, lui,
    # veut des chemins exacts : le catalogue garde ceux de chaque identite.
    def decided_keys(self):
        """Programmes deja tranches pour le profil actif (oui ou non)."""
        if self.profile.get("allow_all"):
            return set()
        return set(self.profile["apps"].keys())

    def allowed_keys(self):
        return {k for k, v in self.profile["apps"].items() if v}

    def blocked_keys(self):
        return {k for k, v in self.profile["apps"].items() if not v}

    def note_path(self, path):
        """Range un chemin exact sous son identite. Renvoie (cle, nouveau)."""
        path = (path or "").lower()
        key = app_key(path)
        e = self.data["catalog"].setdefault(key, {"name": os.path.basename(key) or key,
                                                  "first_seen": time.time()})
        paths = e.setdefault("paths", [])
        if "*" in path or path.startswith("(") or path in paths:
            return key, False
        paths.append(path)
        del paths[:-20]
        return key, True

    def concrete_paths(self, key):
        """Chemins exacts a poser dans le pare-feu pour cette identite : les
        versions vues qui existent encore, sinon celles que le motif retrouve
        sur le disque. "System" designe le trafic du noyau."""
        e = self.data["catalog"].get(key, {})
        out = []
        for p in list(e.get("paths", [])) + ([key] if "*" not in key else []):
            if p.startswith("(") or p in out:
                continue
            if "\\" in p and not os.path.exists(p):
                continue
            out.append(p)
        if not out and "*" in key:
            # seules les etoiles sont des jokers ; un dossier "[x86]" est un nom
            motif = "*".join(glob.escape(morceau) for morceau in key.split("*"))
            try:
                out = sorted({p.lower() for p in glob.glob(motif)})
            except Exception:
                out = []
        return ["System" if p == "system" else p for p in out]

    def set_app(self, path, allow):
        key, _ = self.note_path(path)
        self.profile["apps"][key] = bool(allow)
        return key

    def forget_app(self, key):
        self.profile["apps"].pop(app_key(key), None)

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
        self.data["usage"] = empty_usage(key)
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

    def bonus_bytes(self):
        """Rallonge accordee pour la periode en cours."""
        return int(self.data["usage"].get("bonus", 0) or 0)

    def quota_bytes(self):
        """Enveloppe de la periode, rallonge comprise."""
        return max(1, int(self.data["quota_mb"])) * 1024 * 1024 + self.bonus_bytes()

    def exhausted(self):
        return self.total_used() >= self.quota_bytes()

    def cut_reason(self):
        """Raison de couper Internet, que la protection soit active ou non :
        'plage' (hors plage horaire), 'enveloppe' (epuisee, si la coupure est
        demandee dans les reglages) ou None."""
        if not self.schedule_open():
            return "plage"
        if self.data.get("quota_cut", True) and self.exhausted():
            return "enveloppe"
        return None

    def add_total(self, sent, recv, compte=True):
        """Volume de l'enveloppe, tel que mesure sur la carte reseau.
        compte=False : protection inactive, le volume est mesure et affiche a
        part, sans entamer l'enveloppe."""
        u = self.data["usage"]
        if compte:
            u["total_sent"] += sent
            u["total_recv"] += recv
            pid = self.data["active_profile"]
            u["per_profile"][pid] = u["per_profile"].get(pid, 0) + sent + recv
        else:
            u["off_sent"] = u.get("off_sent", 0) + sent
            u["off_recv"] = u.get("off_recv", 0) + recv
        h = "%02d" % now_in(self.data["tz_mode"]).hour
        per_hour = u.setdefault("per_hour", {})
        per_hour[h] = per_hour.get(h, 0) + sent + recv

    def add_app_usage(self, key, sent, recv, label=None):
        """Trafic Internet d'un programme (detail de la liste)."""
        u = self.data["usage"]
        slot = u["per_app"].setdefault(key, {"sent": 0, "recv": 0,
                                             "name": os.path.basename(key) or key})
        slot["sent"] += sent
        slot["recv"] += recv
        if key.startswith("("):
            return
        cat = self.data["catalog"].setdefault(key, {"name": os.path.basename(key) or key,
                                                    "first_seen": time.time()})
        cat["lifetime"] = cat.get("lifetime", 0) + sent + recv
        if label:
            cat["label"] = label


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
        items.append(pystray.MenuItem("Rallonge pour aujourd'hui...", self._rallonge,
                                      visible=lambda item: self._coupe()))
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Tout debloquer (PANIQUE)", self._panic))
        items.append(pystray.MenuItem("Quitter", self._quit))
        return pystray.Menu(*items)

    def _coupe(self):
        sm = self.app.state_mgr
        return bool(sm.data["engaged"]) and sm.cut_reason() == "enveloppe"

    def _usage_text(self, item=None):
        sm = self.app.state_mgr
        return "%s%s / %s  -  %s" % ("COUPE  -  " if self._coupe() else "",
                                     fmt_bytes(sm.total_used()),
                                     fmt_bytes(sm.quota_bytes()), sm.profile_name())

    def _open(self, icon=None, item=None):
        self.app.after(0, self.app.show_window)

    def _rallonge(self, icon=None, item=None):
        self.app.after(0, self.app.rallonge)

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
            self.icon.title = "%s %s - %s - %s%s / %s" % (
                APP_NAME, VERSION_TXT, sm.profile_name(),
                "COUPE - " if self._coupe() else "",
                fmt_bytes(sm.total_used()), fmt_bytes(sm.quota_bytes()))
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
          "programme par programme. Il compte ce que chacun consomme, te previent "
          "quand ton enveloppe du jour s'epuise, et coupe Internet quand elle est "
          "vide si tu le lui as demande."),

    ("h1", "Le bouton \"Activer la protection\""),
    ("p", "C'est l'interrupteur general."),
    ("h2", "Protection inactive"),
    ("p", "NetGate ne bloque rien. Il regarde, il compte, il te pose des questions et "
          "il retient tes reponses, mais tout le monde sort librement. C'est le mode a "
          "utiliser les premieres heures pour decouvrir qui consomme quoi sans rien "
          "casser."),
    ("h2", "Protection active"),
    ("p", "NetGate donne ses ordres au pare-feu de Windows : le trafic sortant est "
          "refuse par defaut sur les trois profils reseau ; une autorisation est creee "
          "pour chaque programme autorise, une regle de blocage pour chaque programme "
          "bloque ; la regle DNS/DHCP est posee si tu l'as cochee.\n\n"
          "Pourquoi des regles de blocage ? Windows et beaucoup de logiciels "
          "installent leurs propres autorisations (applications du Store, services "
          "Windows, certains logiciels). Elles continuent de laisser passer leur "
          "programme malgre le refus par defaut. Une regle de blocage, elle, "
          "l'emporte toujours : Bloquer veut vraiment dire bloque. Un programme "
          "encore en attente de reponse peut, lui, passer par ces autorisations-la."),
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
          "attendre qu'il se manifeste.\n\n"
          "Un programme mis a jour change souvent de dossier (claude_2.110, puis "
          "claude_2.111...). NetGate le reconnait : une seule ligne, dont le chemin "
          "porte une etoile a la place du numero de version, et ta decision suit la "
          "nouvelle version sans reposer la question. La colonne Fichier montre "
          "l'executable : firefox.exe et pingsender.exe sont deux programmes "
          "distincts du meme logiciel, chacun avec sa decision."),

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
          "A 50, 80 et 100 pour cent, NetGate previent. A 100 pour cent, si la case "
          "\"Couper Internet quand l'enveloppe est epuisee\" est cochee (c'est le "
          "reglage par defaut), il coupe Internet jusqu'a la remise a zero : une "
          "seule regle de blocage vers toutes les adresses Internet, qui passe devant "
          "toutes les autorisations. Localhost et le reseau local restent ouverts. "
          "Besoin de finir quelque chose ? Le bouton \"Rallonge pour aujourd'hui\" "
          "ajoute des Mo pour la journee en cours seulement. La coupure intervient "
          "dans la seconde : quelques Mo peuvent encore passer pendant ce temps.\n\n"
          "L'heure de remise a zero se regle a la minute pres, sur l'heure de ton PC "
          "ou sur l'heure UTC selon ce qu'impose ton fournisseur d'acces."),

    ("h1", "Ce qui est compte"),
    ("p", "L'enveloppe est mesuree sur la carte reseau par laquelle passent les "
          "donnees (Wi-Fi, Ethernet, cle 4G, partage de connexion), comme le "
          "compteur de ton operateur : en-tetes compris, machines virtuelles "
          "comprises. Ce qui reste dans le PC n'y passe pas : un serveur WAMP, "
          "MySQL ou PHP interroge en localhost ne coute rien. Le trafic avec le "
          "reseau local (imprimante, NAS, autre PC) est retire du compte. Les cartes "
          "virtuelles (VPN, VirtualBox, Hyper-V) ne sont pas comptees : leur trafic "
          "sort deja par la carte physique. Reglages, bouton \"Cartes decomptees\", "
          "pour changer ce choix.\n\n"
          "La colonne Consomme de la liste montre, programme par programme, le "
          "trafic echange avec Internet. Avec un VPN, le programme et le VPN "
          "comptent chacun leur part : la liste peut alors depasser l'enveloppe, "
          "qui reste juste."),

    ("h1", "Les plages horaires"),
    ("p", "Reglages, bouton \"Plages horaires\" : un tableau des 48 demi-heures de la "
          "journee. Coche celles pendant lesquelles Internet est autorise. En dehors, "
          "plus rien ne sort vers Internet, meme les programmes de ta liste, quel "
          "que soit le profil ; localhost et reseau local restent ouverts. Les memes horaires "
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
          "Le bandeau indique \"sans detail par programme\" : le module pywintrace "
          "n'est pas installe, ou NetGate tourne sans droits administrateur. "
          "L'enveloppe reste mesuree sur la carte reseau.\n"
          "Un programme bloque passe quand meme : il est peut-etre encore en attente "
          "de reponse, et profite d'une autorisation que Windows ou son installateur "
          "a posee. Reponds Bloquer : une regle de blocage l'emporte sur toutes les "
          "autorisations.\n"
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
        # Pare-feu : l'interface calcule la cible, un fil d'arriere-plan
        # l'applique et tient a jour ce qui est reellement pose.
        self._fw_lock = threading.Lock()
        self._fw_busy = False
        self._fw_pending = False
        self._fw_full = False
        self._fw_target = None
        self._fw_msgs = queue.Queue()
        self.applied = {"engaged": None, "allow": set(), "block": set(),
                        "cut": None, "ess": None, "lockdown": None}
        self._cut_state = "?"     # raison de coupure au dernier passage
        self.sort_key = "acces"   # colonne de tri de la liste principale
        self.sort_desc = False
        self.rates = {}           # programme -> octets/seconde (instantane)
        self.rate_total = 0.0     # debit de l'enveloppe, octets/seconde
        self._lan_reste = [0, 0]  # reseau local deja vu par ETW, pas encore retire
        self._last_tick = time.time()
        self._tick = 0
        self._derniere_erreur = ""

        self.meter = EtwMeter()
        self.nic = NicMeter()
        # d'ou vient l'enveloppe : "carte", "etw" (estimation) ou None
        self.env_source = "carte" if self.nic.available else ("etw" if _etw else None)
        self.scanner = ConnScanner(self.pending_q)
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
        self.nic.poll(self._nic_counted)     # point de depart des compteurs
        self._refresh_addresses()
        self._sync_watch()
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
        # n'apparait que lorsque l'enveloppe epuisee a coupe Internet
        self.btn_rallonge = self._btn(left, "Rallonge pour aujourd'hui...",
                                      self.rallonge, "warn")

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

        # "Fichier" montre toujours l'executable : deux programmes d'un meme
        # logiciel (firefox.exe, pingsender.exe) ne passent plus pour un
        # doublon. La colonne "key", masquee, porte l'identite du programme.
        cols = ("app", "file", "acces", "conso", "path", "key")
        heads = (("app", "Application", 230, "w"),
                 ("file", "Fichier", 150, "w"),
                 ("acces", "Acces", 95, "center"),
                 ("conso", "Consomme", 95, "e"),
                 ("path", "Emplacement", 300, "w"))
        self.tv_apps = ttk.Treeview(f, columns=cols, displaycolumns=cols[:-1],
                                    show="headings", selectmode="browse")
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
        try:
            self._restore_now()
            log_line("fermeture : regles NETGATE_ supprimees, sortant retabli")
        except Exception:
            log_error("nettoyage du pare-feu a la fermeture")
        self.state_mgr.save()
        self.meter.stop()
        self.scanner.stop()
        self.tray.stop()
        self.destroy()

    # -------------------------------------------------------------- moteur
    def _all_known_paths(self):
        """Tous les chemins exacts pour lesquels une regle a pu etre posee."""
        sm = self.state_mgr
        paths = set()
        for key, e in sm.data["catalog"].items():
            if key.startswith("("):
                continue
            paths.update(e.get("paths", []))
            if "*" not in key:
                paths.add(key)
        for prof in sm.data["profiles"].values():
            paths.update(k for k in prof.get("apps", {}) if "*" not in k)
        paths |= self.applied["allow"] | self.applied["block"]
        paths.discard("")
        return paths

    def _fw_plan(self):
        """Ce que le pare-feu doit contenir maintenant. Calcule dans le fil
        de l'interface, seul a modifier l'etat ; le fil du pare-feu n'a plus
        qu'a appliquer la difference."""
        sm = self.state_mgr
        d = sm.data
        plan = {"engaged": bool(d["engaged"]), "known": self._all_known_paths(),
                "libre": bool(sm.profile.get("allow_all")), "nom": sm.profile_name(),
                "allow": set(), "block": set(), "labels": {},
                "cut": sm.cut_reason(), "ess": bool(d["essentials_dns"])}
        plan["lockdown"] = not plan["libre"]
        if not plan["engaged"] or plan["libre"]:
            return plan
        for keys, cible in ((sm.allowed_keys(), plan["allow"]),
                            (sm.blocked_keys(), plan["block"])):
            for k in keys:
                # une regle de blocage sur svchost l'emporterait aussi sur la
                # regle DNS/DHCP : plus aucun nom ne se resoudrait. svchost
                # bloque reste donc a la politique par defaut.
                if cible is plan["block"] and os.path.basename(k) == "svchost.exe":
                    continue
                lab = d["catalog"].get(k, {}).get("label") or ""
                for p in sm.concrete_paths(k):
                    cible.add(p)
                    plan["labels"][p] = lab
        plan["block"] -= plan["allow"]
        return plan

    def apply_firewall(self, full=False):
        """Ne touche que ce qui change, et travaille en arriere-plan pour que
        l'interface reponde immediatement."""
        try:
            target = self._fw_plan()
        except Exception:
            log_error("preparation des regles du pare-feu")
            return
        with self._fw_lock:
            self._fw_target = target
            self._fw_pending = True
            self._fw_full = self._fw_full or full
            if self._fw_busy:
                return
            self._fw_busy = True
        self.status("Application des regles...")
        threading.Thread(target=self._fw_worker, daemon=True, name="Firewall").start()

    def _fw_worker(self):
        # aucun appel a Tk depuis ce fil : les messages passent par une file
        # que la boucle rapide affiche
        while True:
            with self._fw_lock:
                if not self._fw_pending:
                    self._fw_busy = False
                    return
                self._fw_pending = False
                full, self._fw_full = self._fw_full, False
                target = self._fw_target
            try:
                msg = self._fw_sync(target, full)
            except Exception:
                log_error("application des regles au pare-feu")
                msg = "Erreur pare-feu, voir netgate.log"
                with self._fw_lock:
                    self._fw_full = True        # la prochaine fois, tout reprendre
            self._fw_msgs.put(msg)

    def _fw_wait_idle(self, timeout=20.0):
        """Annule ce qui restait a appliquer et attend la fin du fil du
        pare-feu : un nettoyage ne doit pas etre suivi d'une ecriture en
        retard qui reposerait des regles."""
        with self._fw_lock:
            self._fw_pending = False
        fin = time.time() + timeout
        while time.time() < fin:
            with self._fw_lock:
                if not self._fw_busy:
                    return
            time.sleep(0.05)

    def _restore_now(self):
        """Retour immediat a un pare-feu sans NetGate (PANIQUE, fermeture,
        effacement des autorisations)."""
        self.state_mgr.data["engaged"] = False
        self._fw_wait_idle()
        Firewall.panic_restore(self._all_known_paths())
        self.applied = {"engaged": False, "allow": set(), "block": set(),
                        "cut": False, "ess": False, "lockdown": False}

    def _fw_sync(self, t, full):
        a = self.applied
        debut = time.time()
        lines = []

        if not t["engaged"]:
            if full or a["engaged"] is not False:
                lines += Firewall.line_lockdown(False)
                lines += Firewall.lines_cut(False)
                for p in (t["known"] | a["allow"] | a["block"]) if full \
                        else (a["allow"] | a["block"]):
                    lines += Firewall.line_delete(p)
                lines += Firewall.lines_essentials(False)
            Firewall.run_script(lines)
            self.applied = {"engaged": False, "allow": set(), "block": set(),
                            "cut": False, "ess": False, "lockdown": False}
            return "Protection desactivee"

        if full:
            for p in t["known"] - t["allow"] - t["block"]:
                lines += Firewall.line_delete(p)
            # chaque ajout retire d'abord sa propre regle ; l'autre sorte de
            # regle peut exister d'avant (programme passe de bloque a autorise)
            for p in t["allow"]:
                lines += Firewall.line_delete(p, ("BLK",))
            for p in t["block"]:
                lines += Firewall.line_delete(p, ("OUT",))
            add_allow, add_block = t["allow"], t["block"]
        else:
            for p in a["allow"] - t["allow"]:
                lines += Firewall.line_delete(p, ("OUT",))
            for p in a["block"] - t["block"]:
                lines += Firewall.line_delete(p, ("BLK",))
            add_allow, add_block = t["allow"] - a["allow"], t["block"] - a["block"]
        for p in sorted(add_allow):
            lines += Firewall.line_allow(p, t["labels"].get(p, ""))
        for p in sorted(add_block):
            lines += Firewall.line_block(p, t["labels"].get(p, ""))
        if full or t["ess"] != a["ess"]:
            lines += Firewall.lines_essentials(t["ess"])
        coupe = bool(t["cut"])
        if full or coupe != a["cut"]:
            lines += Firewall.lines_cut(coupe)
        # la politique en dernier : les autorisations sont deja en place
        if full or t["lockdown"] != a["lockdown"]:
            lines += Firewall.line_lockdown(t["lockdown"])

        Firewall.run_script(lines)
        self.applied = {"engaged": True, "allow": set(t["allow"]),
                        "block": set(t["block"]), "cut": coupe, "ess": t["ess"],
                        "lockdown": t["lockdown"]}
        if t["cut"] == "enveloppe":
            return ("Enveloppe epuisee : Internet coupe jusqu'a la remise a zero "
                    "(localhost et reseau local restent ouverts)")
        if t["cut"] == "plage":
            suite = self.state_mgr.schedule_next_change()
            return ("Hors plage horaire : Internet coupe" +
                    (" jusqu'a %s" % suite[1] if suite else ""))
        if t["libre"]:
            return "Profil %s : aucun filtrage, le compteur tourne" % t["nom"]
        if not lines:
            return ("Protection active - %d programmes autorises, %d bloques"
                    % (len(t["allow"]), len(t["block"])))
        return ("Regles a jour en %.1f s : %d programmes autorises, %d bloques"
                % (time.time() - debut, len(t["allow"]), len(t["block"])))

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
        self._sync_watch()
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
        self._restore_now()
        self.state_mgr.save()
        self.refresh_all()
        self.status("Internet retabli, regles NetGate supprimees.")

    def rallonge(self):
        """Ajoute des Mo a l'enveloppe, pour la periode en cours seulement :
        le reglage de l'enveloppe ne change pas, la rallonge disparait a la
        remise a zero."""
        from tkinter import simpledialog
        sm = self.state_mgr
        n = simpledialog.askinteger(
            "Rallonge",
            "Combien de Mo ajouter a l'enveloppe, pour aujourd'hui seulement ?\n\n"
            "Consomme : %s sur %s." % (fmt_bytes(sm.total_used()),
                                       fmt_bytes(sm.quota_bytes())),
            parent=self, minvalue=1, maxvalue=1000000, initialvalue=50)
        if not n:
            return
        sm.data["usage"]["bonus"] = sm.bonus_bytes() + n * 1024 * 1024
        log_line("rallonge de %d Mo pour la periode %s" % (n, sm.data["usage"]["period"]))
        self._icon_sig = None
        sm.save()
        self._check_cut()
        self.refresh_all()
        self.refresh_window_icon()
        self.tray.refresh()
        self.status("Rallonge de %d Mo accordee jusqu'a la remise a zero" % n)

    # --------------------------------------------------------- decisions
    def _sync_watch(self):
        """Le scanner surveille les nouvelles versions des programmes tranches."""
        self.scanner.watch = frozenset(self.state_mgr.profile["apps"].keys())

    def _on_scanned(self, item):
        """Tri de ce que remonte le scanner. Renvoie True si une demande
        rejoint la liste d'attente."""
        sm = self.state_mgr
        key, nouveau = sm.note_path(item["path"])
        item["key"] = key
        if key in sm.profile["apps"]:
            # nouvelle version d'un programme deja tranche : la decision
            # suit, sans reposer la question
            if nouveau and sm.data["engaged"]:
                self.apply_firewall()
            return False
        if item.get("src") != "conn" or key in sm.decided_keys():
            return False
        if any(p.get("key") == key for p in self.pending):
            return False
        if self.toast is not None and self.toast.item.get("key") == key:
            return False
        self.pending.append(item)
        return True

    def apply_decision(self, path, allow):
        """path : chemin exact (carte de demande) ou identite (liste)."""
        sm = self.state_mgr
        key = sm.set_app(path, allow)
        self._sync_watch()
        if sm.data["engaged"]:
            self.apply_firewall()
        self.pending = [p for p in self.pending if p.get("key") != key]
        self.refresh_pending_label()
        sm.save()
        self.refresh_apps()
        self.status("%s : %s dans le profil %s"
                    % (self.label_for(key), "autorise" if allow else "bloque",
                       sm.profile_name()))

    def on_toast_decision(self, item, value):
        self.toast = None
        if value is None:
            if not any(p.get("key") == item.get("key") for p in self.pending):
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
            if item.get("key") in self.state_mgr.profile["apps"]:
                self.pending.pop(0)
                continue
            break
        if not self.pending:
            return
        item = self.pending.pop(0)
        lifetime = self.state_mgr.data["catalog"].get(
            item.get("key"), {}).get("lifetime", 0)
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
        return self.tv_apps.item(sel[0], "values")[5]

    def _concrete(self, key):
        """Un chemin reel pour une identite : la version la plus recente."""
        paths = self.state_mgr.concrete_paths(key)
        return paths[-1] if paths else key

    def label_for(self, key):
        """Nom comprehensible : description du fichier, sinon glossaire,
        sinon nom brut. Mis en cache dans le catalogue."""
        if not key or key.startswith("("):
            return "Trafic non attribue" if key else "?"
        key = key.lower()
        cat = self.state_mgr.data["catalog"].get(key)
        if cat and cat.get("label"):
            return cat["label"]
        try:
            lab = Inspector.fast(self._concrete(key), None)["titre"] or os.path.basename(key)
        except Exception:
            lab = os.path.basename(key)
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
            self._check_cut()
            if sm.data["engaged"]:
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
        sm.data["usage"] = empty_usage(sm.period_key())
        sm.data["alerts_fired"] = []
        self.rates = {}
        self._icon_sig = None
        sm.save()
        self._check_cut()
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
            self._restore_now()
        if tout:
            try:
                os.remove(STATE_FILE)
            except Exception:
                pass
            sm.data = json.loads(json.dumps(DEFAULT_STATE))
        else:
            if jour:
                sm.data["usage"] = empty_usage(sm.period_key())
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
        self._sync_watch()
        self._check_cut()
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
        key = self.selected_path()
        if not key:
            return
        pid, path = None, self._concrete(key)
        for it in self.pending:
            if it.get("key") == key:
                pid, path = it.get("pid"), it["path"]
                break
        info = Inspector.fast(path, pid)
        col, lab = NIVEAU_STYLE.get(info["niveau"], NIVEAU_STYLE["utile"])
        self.lbl_info_titre.configure(
            text=self._court(info["titre"] or os.path.basename(path), 90), fg=col)
        cat = self.state_mgr.data["catalog"].get(key, {})

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
        cur = self.state_mgr.profile["apps"].get(p, False)
        self.apply_decision(p, not cur)

    def remove_app(self):
        p = self.selected_path()
        if not p:
            return
        self.state_mgr.forget_app(p)
        self.scanner.forget(p)
        self._sync_watch()
        self.pending = [it for it in self.pending if it.get("key") != p]
        self.refresh_pending_label()
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
        v_cut = tk.BooleanVar(value=d.get("quota_cut", True))

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

        for label, var in (("Couper Internet quand l'enveloppe est epuisee", v_cut),
                           ("Autoriser DNS/DHCP (indispensable en mode protege)", v_dns),
                           ("Afficher une notification a chaque demande", v_notif),
                           ("Demarrer reduit dans la zone de notification", v_min)):
            ttk.Checkbutton(frm, text=label, variable=var).grid(
                row=r, column=0, columnspan=2, sticky="w", pady=5)
            r += 1

        tk.Label(frm, bg=C_PANEL, fg=C_TXT_DIM, justify="left", wraplength=430,
                 font=("Segoe UI", 8),
                 text=("Enveloppe epuisee, protection active : Internet est coupe "
                       "jusqu'a la remise a zero, localhost et reseau local restent "
                       "ouverts, et une rallonge du jour reste possible. Case "
                       "decochee : NetGate previent seulement (50 %, 80 %, 100 %).")
                 ).grid(row=r, column=0, columnspan=2, sticky="w", pady=(12, 4))
        r += 1

        zcarte = tk.Frame(frm, bg=C_PANEL)
        zcarte.grid(row=r, column=0, columnspan=2, sticky="w", pady=(10, 0))
        lbl_cartes = tk.Label(zcarte, bg=C_PANEL, fg=C_TXT_DIM, font=("Segoe UI", 9))

        def maj_cartes():
            noms = self._counted_names()
            lbl_cartes.configure(text="  enveloppe mesuree sur : " +
                                 (", ".join(noms) if noms else "aucune carte"))

        self._btn(zcarte, "Cartes decomptees...",
                  lambda: self.open_nics(w, maj_cartes)).pack(side="left")
        lbl_cartes.pack(side="left")
        maj_cartes()
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
            d["quota_cut"] = bool(v_cut.get())
            d["essentials_dns"] = bool(v_dns.get())
            self.state_mgr.roll_period_if_needed()
            self.state_mgr.save()
            self._icon_sig = None
            self._check_cut()
            if d["engaged"]:
                self.apply_firewall()       # DNS/DHCP, coupure : seul ce qui change
            self.refresh_all()
            self.refresh_window_icon()
            self.tray.refresh()
            w.destroy()
            self.status("Reglages enregistres")

        bar = tk.Frame(frm, bg=C_PANEL)
        bar.grid(row=r, column=0, columnspan=2, sticky="e", pady=(14, 0))
        self._btn(bar, "Annuler", w.destroy).pack(side="right", padx=(8, 0))
        self._btn(bar, "Enregistrer", save, "accent").pack(side="right")

    def open_nics(self, parent=None, on_close=None):
        """Choix des cartes reseau dont le trafic entame l'enveloppe. Par
        defaut : les cartes physiques (Wi-Fi, Ethernet, cle 4G, Bluetooth)."""
        d = self.state_mgr.data
        try:
            # releve frais, sans toucher aux points de depart du comptage
            toutes = self.nic.read() if self.nic.available else []
        except Exception:
            toutes = self.nic.ifaces
        cartes = [it for it in toutes
                  if it["physique"] or it["guid"] in d["nic_include"]
                  or (it["up"] and (it["rx"] or it["tx"]))]
        w = tk.Toplevel(parent or self)
        w.title("Cartes decomptees")
        w.configure(bg=C_PANEL)
        w.resizable(False, False)
        w.transient(parent or self)
        w.grab_set()
        frm = tk.Frame(w, bg=C_PANEL)
        frm.pack(padx=24, pady=20)
        tk.Label(frm, text="Cartes reseau decomptees", bg=C_PANEL, fg=C_TXT,
                 font=("Segoe UI Semibold", 13)).pack(anchor="w")
        tk.Label(frm, bg=C_PANEL, fg=C_TXT_DIM, justify="left", wraplength=520,
                 font=("Segoe UI", 9),
                 text=("L'enveloppe compte ce qui passe par les cartes cochees, "
                       "comme le compteur de l'operateur. Localhost (serveurs "
                       "locaux, WAMP, MySQL) ne passe par aucune carte, et le "
                       "trafic du reseau local est retire. Ne coche pas une carte "
                       "virtuelle (VPN, VirtualBox, Hyper-V) : son trafic sort deja "
                       "par la carte physique, il serait compte deux fois.")
                 ).pack(anchor="w", pady=(2, 12))
        choix = {}
        if not cartes:
            tk.Label(frm, bg=C_PANEL, fg=C_WARN, font=("Segoe UI", 9),
                     text="Aucune carte lisible : l'enveloppe est estimee programme "
                          "par programme.").pack(anchor="w")
        for it in sorted(cartes, key=lambda i: (not i["physique"], i["alias"].lower())):
            v = tk.BooleanVar(value=self._nic_counted(it))
            choix[it["guid"]] = (it, v)
            ttk.Checkbutton(frm, text="%s  -  %s" % (it["alias"], it["desc"]),
                            variable=v).pack(anchor="w", pady=(4, 0))
            tk.Label(frm, bg=C_PANEL, fg=C_TXT_DIM, font=("Segoe UI", 8),
                     text="%s, %s, %s depuis le demarrage de Windows" % (
                         "physique" if it["physique"] else "virtuelle",
                         "connectee" if it["up"] else "deconnectee",
                         fmt_bytes(it["rx"] + it["tx"]))).pack(anchor="w", padx=24)

        def enregistrer():
            absentes_ex = [g for g in d["nic_exclude"] if g not in choix]
            absentes_in = [g for g in d["nic_include"] if g not in choix]
            d["nic_exclude"] = [g for g, (it, v) in choix.items()
                                if it["physique"] and not v.get()] + absentes_ex
            d["nic_include"] = [g for g, (it, v) in choix.items()
                                if not it["physique"] and v.get()] + absentes_in
            self.state_mgr.save()
            self._refresh_addresses()
            w.destroy()
            if on_close:
                on_close()

        bar = tk.Frame(frm, bg=C_PANEL)
        bar.pack(fill="x", pady=(16, 0))
        self._btn(bar, "Annuler", w.destroy).pack(side="right", padx=(8, 0))
        self._btn(bar, "Enregistrer", enregistrer, "accent").pack(side="right")

    # -------------------------------------------------------- rafraichis.
    def refresh_header(self):
        sm = self.state_mgr
        d = sm.data
        used, quota = sm.total_used(), sm.quota_bytes()
        pct = used / float(quota)
        self.lbl_used.configure(text=fmt_bytes(used))
        hors = sm.off_used()
        txt = "sur %d Mo" % d["quota_mb"]
        if sm.bonus_bytes():
            txt += " + %s de rallonge" % fmt_bytes(sm.bonus_bytes())
        txt += "  -  %.0f %% de l'enveloppe" % (100 * pct)
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
        ligne = ("Remise a zero dans %02d h %02d min %02d s (a %02d:%02d, heure %s)"
                 % (hh, mm, ss, d["reset_hh"], d["reset_mm"],
                    "UTC" if d["tz_mode"] == "utc" else "du PC"))
        couleur = C_TXT_DIM
        raison = sm.cut_reason() if d["engaged"] else None
        suite = sm.schedule_next_change()
        if raison == "plage":
            ligne = ("INTERNET COUPE (hors plage horaire)" +
                     ("   -   reouverture a %s" % suite[1] if suite else ""))
            couleur = C_DANGER
        elif raison == "enveloppe":
            ligne = ("INTERNET COUPE : enveloppe epuisee, retour a la remise a zero "
                     "dans %02d h %02d min" % (hh, mm))
            couleur = C_DANGER
        elif d.get("schedule_enabled") and suite:
            ligne += ("   |   plage ouverte jusqu'a %s" % suite[1] if sm.schedule_open()
                      else "   |   hors plage jusqu'a %s" % suite[1])
        self.lbl_reset.configure(text=ligne, fg=couleur)
        # le bouton de rallonge n'a de sens que pendant la coupure
        if (raison == "enveloppe") != bool(self.btn_rallonge.winfo_manager()):
            if raison == "enveloppe":
                self.btn_rallonge.pack(anchor="w", pady=(8, 0))
            else:
                self.btn_rallonge.pack_forget()
        live = self.rate_total
        if live > 1024:
            txt = "%s/s en ce moment" % fmt_bytes(live)
            gros = max(self.rates.items(), key=lambda kv: kv[1]) if self.rates else None
            if gros and gros[1] > 0:
                txt += "  -  surtout %s" % self.label_for(gros[0])
            self.lbl_debit.configure(text=txt,
                                     fg=C_WARN if live > 200 * 1024 else C_ACCENT)
        else:
            self.lbl_debit.configure(text="Trafic au repos", fg=C_TXT_DIM)
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
        if self.env_source == "carte":
            noms = self._counted_names(connectees=True) or self._counted_names()
            lignes = ["enveloppe mesuree sur : %s" % (", ".join(noms) or "?")]
        elif self.env_source == "etw":
            lignes = ["enveloppe estimee programme par programme"]
        else:
            lignes = ["aucun comptage disponible"]
        lignes.append("detail par programme" if self.meter.mode == "etw"
                      else "sans detail par programme")
        local = d["usage"].get("local", 0)
        if local:
            lignes.append("localhost et reseau local ecartes : %s" % fmt_bytes(local))
        self.lbl_engine.configure(text="\n".join(lignes), justify="right")

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
        selval = self.tv_apps.item(sel[0], "values")[5] if sel else None
        self.tv_apps.delete(*self.tv_apps.get_children())

        entries = dict(sm.profile["apps"])
        for it in self.pending:
            entries.setdefault(it.get("key") or app_key(it["path"]), None)
        noms = {k: self.label_for(k) for k in entries}

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
            if self.sort_key == "file":
                return (os.path.basename(path), path)
            if self.sort_key == "path":
                return path
            return noms[path].lower()

        rows = sorted(entries.items(), key=key_of, reverse=self.sort_desc)

        # rappel visuel de la colonne de tri
        libelles = {"app": "Application", "file": "Fichier", "acces": "Acces",
                    "conso": "Consomme", "path": "Emplacement"}
        fleche = " v" if self.sort_desc else " ^"
        for c, t in libelles.items():
            self.tv_apps.heading(c, text=t + (fleche if c == self.sort_key else ""))

        for path, allowed in rows:
            conso = conso_of(path)
            if allowed is None:
                etat, tag = "en attente", "wait"
            elif allowed:
                etat, tag = "autorise", "allow"
            else:
                etat, tag = "bloque", "block"
            self.tv_apps.insert("", "end", tags=(tag,),
                                values=(noms[path], os.path.basename(path), etat,
                                        fmt_bytes(conso), os.path.dirname(path) or "-",
                                        path))
        if selval:
            for iid in self.tv_apps.get_children():
                if self.tv_apps.item(iid, "values")[5] == selval:
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
            try:
                new = self._on_scanned(item) or new
            except Exception:
                log_error("traitement d'une detection")
        while True:
            try:
                self.status(self._fw_msgs.get_nowait())
            except queue.Empty:
                break
        if new:
            self.refresh_pending_label()
            self.refresh_apps()
        if self.toast is None and self.pending and self.state_mgr.data["notify_enabled"]:
            self._show_next_toast()
        self.after(500, self._loop_fast)

    def _loop_slow(self):
        """Chaque seconde : comptage, puis coupure des que l'enveloppe se
        vide. Affichage et sauvegarde suivent toutes les deux secondes. Une
        erreur ne doit jamais arreter la boucle : c'est elle qui coupe."""
        sm = self.state_mgr
        self._tick += 1
        try:
            if sm.roll_period_if_needed():
                self._icon_sig = None
                self.status("Nouvelle journee - compteurs remis a zero")
                self.tray.notify(APP_NAME, "Nouvelle enveloppe : %d Mo disponibles."
                                 % sm.data["quota_mb"])
            if self._tick % 30 == 0:
                self._refresh_addresses()
            self._account()
            self._check_cut()
            self.check_alerts()
            if self._tick % 2 == 0:
                if self.state().lower() != "withdrawn":
                    self.refresh_all()
                self.refresh_window_icon()
                self.tray.refresh()
                sm.save()
        except Exception:
            # une meme erreur a chaque seconde ne doit pas remplir le journal
            trace = traceback.format_exc()
            if trace != self._derniere_erreur:
                self._derniere_erreur = trace
                log_error("boucle de comptage")
        self.after(1000, self._loop_slow)

    # ---------------------------------------------------------- comptage
    def _nic_counted(self, it):
        """Une carte entame-t-elle l'enveloppe ? Physique par defaut, sauf
        choix contraire dans les reglages."""
        d = self.state_mgr.data
        if it["guid"] in d.get("nic_include", []):
            return True
        return it["physique"] and it["guid"] not in d.get("nic_exclude", [])

    def _counted_names(self, connectees=False):
        return [it["alias"] for it in self.nic.ifaces
                if self._nic_counted(it) and (it["up"] or not connectees)]

    def _refresh_addresses(self):
        """Adresses de la machine, pour que le comptage par programme separe
        localhost, reseau local et Internet."""
        if psutil is None:
            return
        try:
            cartes = psutil.net_if_addrs()
        except Exception:
            return
        comptees = set(self._counted_names())
        own, counted, prefixes = {"127.0.0.1", "::1"}, set(), set()
        for nom, addrs in cartes.items():
            for a in addrs:
                if a.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                try:
                    ip = ipaddress.ip_address(a.address.split("%")[0])
                except ValueError:
                    continue
                own.add(str(ip))
                if nom in comptees:
                    counted.add(str(ip))
                if ip.version == 6 and (int(ip) >> 125) == 1:     # 2000::/3
                    prefixes.add(int(ip) >> 64)
        self.meter.set_addresses(frozenset(own), frozenset(counted), frozenset(prefixes))

    def _account(self):
        """Releve d'une seconde. Le detail par programme vient d'ETW (trafic
        Internet seulement) ; l'enveloppe vient des compteurs des cartes
        decomptees, moins le reseau local qu'ETW y a vu passer."""
        sm = self.state_mgr
        now = time.time()
        dt = max(0.5, now - self._last_tick)
        self._last_tick = now
        etw = self.meter.drain()

        tick = {}
        for pid, (s, r) in etw["apps"].items():
            exe = self.scanner.exe_for(pid) if psutil else None
            # app_key seul, sans ranger le chemin : c'est au scanner de
            # signaler une nouvelle version, pour que ses regles suivent
            key = app_key(exe) if exe else UNATTRIBUTED
            sm.add_app_usage(key, s, r, label=self.label_for(key))
            tick[key] = tick.get(key, 0) + s + r
        self.rates = {k: v / dt for k, v in tick.items()}

        nic = self.nic.poll(self._nic_counted)
        if nic is not None and any(self._nic_counted(it) for it in self.nic.ifaces):
            s, r = nic
            # les evenements ETW arrivent par paquets : ce qui n'a pas pu
            # etre retire ce tour-ci l'est au suivant, pas au-dela
            ls, lr = etw["lan"][0] + self._lan_reste[0], etw["lan"][1] + self._lan_reste[1]
            ms, mr = min(s, ls), min(r, lr)
            self._lan_reste = [min(ls - ms, etw["lan"][0]), min(lr - mr, etw["lan"][1])]
            s, r = s - ms, r - mr
            self.env_source = "carte"
        elif self.meter.mode == "etw":
            s, r = etw["inet"]
            self.env_source = "etw"
        else:
            s = r = 0
            self.env_source = None
        if s or r:
            sm.add_total(s, r, compte=bool(sm.data["engaged"]))
        sm.data["usage"]["local"] = sm.data["usage"].get("local", 0) + etw["local"]
        self.rate_total = (s + r) / dt

    def _check_cut(self):
        """Suit la raison de couper Internet ; au changement, previent et
        met le pare-feu a jour. Protection inactive, rien n'est coupe."""
        sm = self.state_mgr
        raison = sm.cut_reason()
        if raison == self._cut_state:
            return
        avant, self._cut_state = self._cut_state, raison
        if not sm.data["engaged"]:
            return
        if avant != "?":
            if raison == "plage":
                suite = sm.schedule_next_change()
                msg = "Plage horaire fermee : Internet coupe" + (
                    " jusqu'a %s" % suite[1] if suite else "")
            elif raison == "enveloppe":
                msg = ("Enveloppe epuisee : Internet coupe jusqu'a la remise a zero "
                       "de %02d:%02d. Rallonge possible depuis la fenetre ou l'icone."
                       % (sm.data["reset_hh"], sm.data["reset_mm"]))
            elif avant == "plage":
                msg = "Plage horaire ouverte : Internet retabli"
            else:
                msg = "Enveloppe renouvelee : Internet retabli"
            self.status(msg)
            self.tray.notify(APP_NAME, msg)
            log_line(msg)
        self.apply_firewall()

    def check_alerts(self):
        sm = self.state_mgr
        pct = 100.0 * sm.total_used() / sm.quota_bytes()
        for seuil in sorted(sm.data["alert_pct"]):
            if pct >= seuil and seuil not in sm.data["alerts_fired"]:
                sm.data["alerts_fired"].append(seuil)
                coupe = (seuil >= 100 and sm.data["engaged"]
                         and sm.data.get("quota_cut", True))
                msg = ("%d %% de l'enveloppe consommes (%s sur %s). %s"
                       % (seuil, fmt_bytes(sm.total_used()), fmt_bytes(sm.quota_bytes()),
                          "Internet est coupe jusqu'a la remise a zero ; une rallonge "
                          "reste possible." if coupe else "Rien n'est coupe."))
                if not coupe:       # la coupure a deja fait sa notification
                    self.tray.notify(APP_NAME, msg)
                if self.state().lower() != "withdrawn":
                    # differe : la boucle de comptage n'attend pas qu'on ferme
                    # la boite pour continuer a compter
                    self.after(10, lambda m=msg: messagebox.showwarning(
                        "Enveloppe Internet", m, parent=self))

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
                "Sans pywintrace : pas de detail par programme (l'enveloppe reste "
                "mesuree sur la carte reseau).\n"
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
