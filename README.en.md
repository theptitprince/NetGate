<div align="center">

# NetGate — Per-application Internet access control

**The Internet tap is closed; you open it program by program.**

![Version](https://img.shields.io/badge/version-2.3-2ea44f)
![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![tkinter](https://img.shields.io/badge/interface-tkinter-3776AB?logo=python&logoColor=white)
![WFP](https://img.shields.io/badge/filtering-Windows%20Filtering%20Platform-0078D6?logo=windows&logoColor=white)
![ETW](https://img.shields.io/badge/metering-ETW%20%28pywintrace%29-0078D6?logo=windows&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)

</div>

[Français](README.md) · **English**

> The program's interface is in French; its labels are quoted below as they appear on screen.

---

> [!NOTE]
> **Windows 10 or 11, administrator rights.** NetGate filters connections and therefore asks for administrator
> rights at launch; without them, it offers a limited mode in which nothing is blocked. Protection is
> **inactive** until you turn it on: observe first, block later. **Closing the window does not quit**: NetGate
> keeps watching from the notification area, and only *Quitter* (Quit), in its icon's menu, stops it.
> When in doubt, the **PANIQUE** (panic) button restores Internet access immediately.

NetGate counts what each program consumes, warns you when the day's
allowance is running out, and cuts off Internet access when it is empty.

**Who it is for.** Anyone living on a metered connection — mobile
tethering, a 4G dongle, a capped data plan, a satellite link — where every
megabyte counts and where an update started at the wrong moment can drain a
plan in an hour. NetGate places its own filters in the Windows filtering
engine to block everything you have not allowed, asks you what to do as
soon as a program tries to connect out, measures the allowance on the network
adapter the data passes through, attributes to each program what it
exchanges with the Internet, and keeps a daily allowance with alerts at 50,
80 and 100% and a cut-off at 100%. It produces an allow list that carries
over from one launch to the next, a counter per program and per day, and a
shield in the notification area that fills up with your consumption.

Current version: 2.3 — the release history is on the
[releases](https://github.com/theptitprince/NetGate/releases) page, and
summarized at the top of `netgate.py`.

**Download.** The sources are on the
[releases](https://github.com/theptitprince/NetGate/releases) page, or via
`git clone`. To run the script: Python 3.8+ with tkinter, `psutil`,
`pywintrace`, `pystray` and `pillow` — Windows 10 or 11, administrator
rights. A standalone `NetGate.exe`, which does not need Python, is built
with PyInstaller (see “Building an executable”).

## Contents

- [1. Installation](#1-installation)
- [2. The files](#2-the-files)
- [3. Launching](#3-launching)
- [4. Getting started](#4-getting-started)
- [5. How it works](#5-how-it-works)
- [6. What the program creates next to itself](#6-what-the-program-creates-next-to-itself)
- [7. The allowance, the time slots, the profiles](#7-the-allowance-the-time-slots-the-profiles)
- [8. Building an executable](#8-building-an-executable)
- [9. Troubleshooting](#9-troubleshooting)
- [10. License](#10-license)

---

## 1. Installation

With `NetGate.exe`, there is nothing to install: put it in its own folder
and go straight to [launching](#3-launching). What follows concerns the
`netgate.py` script.

### Python

You need **Python 3.8 or newer**, with **tkinter**.

Install Python from <https://www.python.org/downloads/> and **check two
boxes** in the installer:

- `Add Python to PATH` (on the first screen)
- `tcl/tk and IDLE` (on the “Optional Features” screen)

Without the second one, the application cannot open: tkinter is what
draws the whole interface.

To check, open PowerShell and type:

```powershell
python --version
python -m tkinter
```

The first command should display a version number, the second should open
a small test window.

### The libraries

```powershell
python -m pip install psutil pywintrace pystray pillow
```

Strictly speaking, each one is optional: NetGate starts even if one is
missing, with fewer features. The table says which ones, so that you can
make an informed decision.

| Library | What it provides | Without it |
|---|---|---|
| `psutil` | discovery of open connections, network adapter addresses | no program is detected, no notification appears |
| `pywintrace` | per-program metering (Event Tracing for Windows) | the allowance is still measured on the network adapter, without per-program detail |
| `pystray` + `pillow` | the icon in the notification area and its menu | the main window is on its own, with no shield next to the clock; its close button then minimizes it to the taskbar |

### Administrator rights

Filtering connections requires elevation. Launched without these rights,
NetGate itself offers to restart as administrator — *Oui* (Yes), then the
Windows UAC prompt — or to open in **mode limité** (limited mode) — *Non*
(No) — where the interface and the counters work, but nothing is blocked.
It is a good mode for observing before deciding. `NetGate.exe`, for its
part, asks Windows for elevation as soon as it is launched.

---

## 2. The files

Get the repository in either of these ways:

- green **Code → Download ZIP** button on the GitHub page, then unzip the
  archive into a folder (for example `C:\NetGate`);
- or, if you have git:

```powershell
git clone https://github.com/theptitprince/NetGate.git C:\NetGate
```

| File | Role |
|---|---|
| `netgate.py` | the complete program, in a single file |
| `LICENSE` | the text of the program's license (see [License](#10-license)) |
| `NOTICE` | the additional license terms (section 7): the notice to keep |
| `README.md` | the French version of this document |
| `README.en.md` | its English translation (this file) |
| `NetGate.exe` | the standalone executable, to build yourself (see “Building an executable”); it is neither in the repository nor attached to the releases |

Place `netgate.py` (or `NetGate.exe`) **in its own folder**: it creates
its working files there (see
[What the program creates next to itself](#6-what-the-program-creates-next-to-itself)).

### Structure of `netgate.py`

The program fits in **a single file**, organized in sections:

| Section | Role |
|---|---|
| `WfpEngine` | the dynamic session in the Windows filtering engine (WFP): sublayer, filters, transactions |
| `wfp_specs`, `WfpBackend` | translate the allow list into NetGate filters and apply only the differences |
| `Firewall`, `NetshBackend` | the fallback engine: Windows Firewall rules set with `netsh advfirewall` |
| `EtwMeter` | listens to the kernel network tracing (Kernel-Network as a fallback) and attributes to each process the bytes it exchanges with the Internet; spots refused connections |
| `NicMeter` | reads the network adapter counters: the allowance measurement |
| `ConnScanner` | discovers open connections and reports programs with no decision |
| `State` | loads and saves the state file, manages periods and profiles |
| `Inspector` | answers “what is this program?” |
| `AuthToast` | the Autoriser / Bloquer / Plus tard (Allow / Block / Later) card |
| `Tray` | the notification area icon and its menu |
| `NetGateApp` | the main window, the settings, the list, the time slots |

---

## 3. Launching

Open PowerShell in the program's folder and type:

```powershell
python netgate.py
```

If PowerShell is not itself running as administrator, NetGate offers to
restart with these rights: answer *Oui*, then accept the Windows prompt.
The main window opens, and a shield appears in the notification area, next to
the clock. With the executable, double-clicking `NetGate.exe` is enough.

A desktop shortcut is handy: target
`python C:\NetGate\netgate.py`, start in `C:\NetGate`. To
launch NetGate without a console window, replace `python` with `pythonw`.

**Closing the window does not quit**: NetGate keeps watching and blocking
stays active. To stop the program, go through the icon's menu
(*Quitter*). At that point, all of NetGate's filters disappear and the
Internet goes back to normal. This detour is deliberate: closing it by
mistake must never stop the monitoring while leaving you to believe it is
still running.

**One NetGate at a time.** Launching it again while it is already running,
even minimized next to the clock, does not open a second one: its window
reappears (relaunched with `python netgate.py`, it does not even ask for
administrator rights again). Two NetGates would fight over the filtering
engine and the counter.

**Check the engine, once.** Before the first use on a PC, with NetGate
closed, run the self-test:

```powershell
python netgate.py --test-wfp
```

It asks for administrator rights, checks in about twenty seconds that the
filtering engine works on this PC and that per-program metering attributes
traffic correctly, and leaves a report, `netgate-test-wfp.txt`. It touches
nothing but itself: its test filters only target its own connection to a
documentation address (`192.0.2.1`, which does not exist on the Internet)
or to localhost, and disappear at the end; the metering check sends a few
KB to that same address. With the executable:

```powershell
.\NetGate.exe --test-wfp
```

---

## 4. Getting started

The first good habit is to **observe before blocking**. Leave NetGate
running for an hour or two with **protection inactive**: it discovers the
programs that connect out, counts what they consume and remembers your answers,
without cutting anything off. This way you see who consumes what without
risking breaking a work session.

Then:

1. **Réglages** (Settings): daily allowance (in MB), reset time, and the
   *Autoriser DNS/DHCP (indispensable en mode protégé)* (allow DNS/DHCP,
   essential in protected mode) box, to be left checked.
2. **Activer la protection** (enable protection).
3. Open your browser: a card appears at the bottom right; click
   *Autoriser*.
4. Repeat for each program you need. After ten minutes, the requests
   become less frequent: the list is built.

Each request card shows the program's readable name, its publisher, what
it is for and a piece of advice, so that you do not have to guess what
`svchost.exe` or `msedgewebview2.exe` hides. Three answers: *Autoriser*,
*Bloquer*, *Plus tard*. The last one leaves the question open; meanwhile,
the program stays blocked. A card marked *Connexion bloquée* (connection
blocked) indicates a program that has just tried to connect out and was refused:
allow it, and it retries on its own.

---

## 5. How it works

Since Windows Vista, every firewall on Windows, Microsoft's included,
places its filters in the same engine: the **Windows Filtering
Platform** (WFP). NetGate 2 places its own there directly, as ZoneAlarm-style
application firewalls do, with no driver to install and without touching
the Windows Firewall rules.

### Blocking

When protection is active, NetGate opens a session in the engine and
creates its own sublayer there, with the highest priority. In this
sublayer, the highest-weight matching filter decides: localhost open, then
local network open, then the cut-off (allowance used up, outside the time
slots), then one *allow* filter per accepted program, and finally
*everything else is blocked*. Refused programs, or those still pending,
have no filter of their own: the general block applies. Each change is
applied in one go, in a transaction, and only touches the filters that
change.

### Why an engine of its own

Windows and many programs set their own *allow* rules in the Windows
Firewall: Store apps, Windows services, some installers (more than a
hundred on a typical PC). In the Windows Firewall, they let their program
through despite a *block* policy. In the engine, a block in the NetGate
sublayer is final: none of these permissions takes precedence over it.
*Bloquer* really means blocked, and a program waiting for an answer is
blocked too.

### The dynamic session

NetGate's filters belong to a session that Windows deletes as soon as
NetGate stops, whether it quits normally, crashes or is killed. Nothing can
remain blocked without your knowledge, and no cleanup is needed at the next
startup.

### The DNS/DHCP rule

An optional filter, checked by default (the *Autoriser DNS/DHCP* box in
the settings), lets `svchost.exe` through to ports 53 (DNS), 67 and 547
(DHCP). Without it, even allowed programs can no longer resolve any name
when the DNS server is on the Internet (common on 4G), and a modem in
bridge mode no longer renews the PC's address. If everything starts
failing, this is the first setting to check.

### The fallback engine

If the NetGate engine cannot open, or fails along the way, NetGate
switches to the version 1 engine: Windows Firewall rules set with
`netsh advfirewall`, all prefixed `NETGATE_`. The outbound policy switches
to *block*, an *allow* rule is created per accepted program and a *block*
rule per refused program; a block rule overrides all of Windows's
permissions. These rules outlive NetGate: they are removed on quitting,
and at the next startup after an abrupt shutdown. Réglages → *Moteur de
filtrage* (filtering engine) to choose this engine; the banner shows the
engine in use.

### Metering the allowance

The allowance is measured on the network adapter the data passes through
(Wi-Fi, Ethernet, 4G dongle, USB or Bluetooth tethering), with the
counters that Task Manager shows: it is the measurement closest to the
carrier's, headers included, virtual machine traffic included. What stays
inside the PC does not go through it: a WAMP, MySQL or PHP server queried
on localhost costs nothing. Traffic with the local network (NAS, printer,
another PC) is removed from the count. Virtual adapters (VPN tunnel,
VirtualBox, Hyper-V) are not counted: they relay traffic that then goes
out through the physical adapter, and counting them would count it twice.
Réglages → *Cartes décomptées* (metered adapters) to change this choice.

### Per-program detail

NetGate opens its own “system” Event Tracing for Windows session and
receives the kernel network tracing there (the TCP and UDP send and receive
events) to attribute to each process the bytes it exchanges with the
Internet; each event carries both addresses of the connection, which makes
it possible to set aside localhost and the local network. The
`Microsoft-Windows-Kernel-Network` provider carries the same information,
but on Windows 11 (build 26200) its events never arrive in an ordinary
session: it now serves only as a fallback. If `pywintrace` is missing or
no session can start, the allowance is still measured on the adapter,
without per-program detail. With a VPN, the program and the VPN each count
their share: the sum of the list can exceed the allowance, which remains
accurate.

### Discovery

Every 1.5 s, the list of open connections to the Internet is read, and
each executable that has not yet received a decision triggers a request
card. A blocked program, however, never has an open connection: NetGate
therefore also listens to event 1020 of the `Microsoft-Windows-TCPIP`
provider, “connection rejected by the filtering engine”, which gives the
process and the target address. The card then appears marked
*Connexion bloquée*; allow it, and the program retries on its own. A
program that only talks to localhost or the local network triggers
nothing.

### Updates

Many programs change folders with each version
(`152.0.4191.66`, `app-1.0.9187`, `jre1.8.0_381`, or the versioned folder
of a Microsoft Store package). NetGate recognizes them: a single line in
the list, whose location has `*` in place of the version number, and the
decision follows the new version, firewall rule included, without asking
the question again.

### The inspector

To answer “what is this program?”, NetGate combines a French-language
glossary of common processes, the version and publisher read from the
file's resources, the digital signature, the window title, and for
`svchost.exe` the exact Windows service hosted by that process.

### Recovery

The **PANIQUE** button closes the NetGate session: all filters disappear
immediately and Internet access comes back. If the previous session used
the fallback engine and was interrupted (power cut, process killed),
NetGate removes at startup the `NETGATE_` rules left in the Windows
Firewall.

---

## 6. What the program creates next to itself

Everything is stored **next to `netgate.py`** (or `NetGate.exe`). If that
folder is not writable (Program Files, write-protected USB stick, network
folder), NetGate automatically falls back to `%APPDATA%\NetGate`.

| File | Contents |
|---|---|
| `netgate.state.json` | settings, profiles, permissions, today's counters, history, catalog of the programs seen. **Copy it to back up your configuration.** Rename it to start from scratch. |
| `netgate.log` | startup trace and any errors: the first file to open when something goes wrong. |
| `netgate.ico` | the shield, regenerated at each change of profile or consumption level, for the window and the executable. |
| `netgate-test-wfp.txt` | the report of the last engine self-test (`--test-wfp`). |
| `netgate.state.json.v2.bak` | copy of the state as it was before its conversion by version 1.4; can be deleted once 1.4 has been validated. |

`netgate.state.json` contains the paths of your programs: it is a
personal file, do not share it as is.

---

## 7. The allowance, the time slots, the profiles

### The program list

Green = allowed, red = blocked, orange = pending. The columns can be
sorted (access, volume), a double-click changes the decision, and the
description panel at the bottom of the window reminds you who the selected
program is. The *Fichier* (file) column shows the executable:
`firefox.exe` and `pingsender.exe` are two distinct programs of the same
software, each with its own decision. *Ajouter un programme* (add a
program) allows something in advance, without waiting for it to show up —
useful for videoconferencing software just before a meeting.

### The daily allowance

- The allowance is **only counted down when protection is active**.
  With protection off, traffic is measured and shown separately: observing
  costs nothing against the quota.
- The reset happens at the chosen time, to the minute, in local time or
  UTC. If the computer is off at that moment, the switchover happens at the
  next startup; if the system clock has gone backwards, the switchover is
  forced so as not to extend the day unduly.
- Alerts at 50, 80 and 100%. At 100%, **Internet access is cut off** until
  the reset: a single block rule to all Internet addresses, which takes
  precedence over all permissions, NetGate's as well as those already set
  in Windows. Localhost and the local network stay open. The cut-off
  happens within a second; a few MB may still get through during that
  delay.
- *Rallonge pour aujourd'hui* (extension for today), in the banner or the
  icon menu during the cut-off, adds MB for the current period only: the
  allowance setting does not change.
- To be warned only, without a cut-off: Réglages → uncheck *Couper
  Internet quand l'enveloppe est épuisée* (cut off the Internet when the
  allowance is used up).
- *Remettre le compteur à zéro* (reset the counter), in the settings,
  starts again from zero without touching the permissions.

### Time slots

Réglages → *Plages horaires* (time slots): a grid of 48 half-hours to
check. Outside the slots, nothing goes out to the Internet any more, not
even allowed programs, whatever the profile; localhost and the local
network stay open. Shortcuts *Tout ouvrir* (open all), *Tout fermer*
(close all), *08h - 22h* (08:00 to 22:00). The banner shows the next
opening or closing, so that you do not wonder why everything stopped at
22:00.

### The icon next to the clock

The shield fills up with consumption (green → orange → red). Right-click:
*Ouvrir NetGate* (open NetGate), the choice of profile (if you have
created any), *À propos...* (about: the legal notices, in the help),
today's consumption against the allowance with the active profile,
*Rallonge pour aujourd'hui* when the allowance is used up,
*Tout débloquer (PANIQUE)* (unblock everything, panic), *Quitter*.

### Profiles

By default, there is a single allow list, and no profile bar clutters the
window. If you create profiles in the settings, a selection bar appears at
the top. Suggested templates, under *Depuis un modèle* (from a template):
*Blackout*, *Essentiel* (essential), *Travail* (work), *Visio* (video
call), each with its own color and indicative budget, and *Libre*
(unrestricted), which filters nothing but keeps the counter running. A
profile is a complete allow list: switching from *Travail* to *Visio*
replaces one with the other.

### Clearing and starting over

The settings let you reset the active list, the counters, the history,
the permissions, or reset everything to its initial state. The firewall rules are
cleaned up before each reset, so that no program stays blocked with no way
to unblock it.

### Built-in help

The **F1** key, or the *Aide F1* (Help F1) button, opens a help screen in
French that covers everything above, directly in the program. Its
*À propos* (about) section, which the icon's menu also opens
(*À propos...*), gives the legal notices: the notice “NetGate, par ETDEL”
with the repository address, the copyright, the license, the absence of
warranty and the additional terms (see [License](#10-license)). The status
bar, at the bottom of the main window, always shows the version and this
notice.

---

## 8. Building an executable

A standalone executable avoids installing Python on the target machine and
asks for UAC elevation by itself. From the source folder:

```powershell
python -m pip install --upgrade pyinstaller psutil pywintrace pystray pillow
```

```powershell
python -c "import netgate; netgate.write_ico(netgate.C_ACCENT, 0.35)"
```

```powershell
python -m PyInstaller --onefile --noconsole --uac-admin --clean --noconfirm --name NetGate --icon netgate.ico --collect-all etw --collect-all pystray --hidden-import pystray._win32 --hidden-import PIL._tkinter_finder netgate.py
```

- `--onefile --noconsole`: a single file, with no console window.
- `--uac-admin`: the executable asks for elevation at launch.
- `--icon netgate.ico`: the shield, generated by the second command.
- `--collect-all` / `--hidden-import`: dynamically loaded modules that
  PyInstaller does not detect on its own.

Allow 2 to 5 minutes. Result: `dist\NetGate.exe`, standalone, about
30 MB, to be placed in its own folder like `netgate.py`. The `build/` and
`dist/` folders and the `NetGate.spec` file can then be deleted. On first
launch, SmartScreen may display a warning (unsigned program): *More info*
→ *Run anyway*.

An overzealous antivirus can block PyInstaller: it is the most common
cause of failure.

**Distributing the executable.** `NetGate.exe` does not embed `LICENSE` or
`NOTICE`. Anyone who distributes it must ship these two files with it (in
the same folder or the same archive) and give access to the corresponding
source code, as the GPL requires. The legal notices themselves are built
into the program (status bar, F1 help).

---

## 9. Troubleshooting

**“No module named tkinter”** — Python was installed without tcl/tk.
Run the installer again, choose *Modify*, and check `tcl/tk and IDLE`.

**“No module named psutil”** (or `etw`, `pystray`, `PIL`) — the
installation command was not run, or was run for another Python. Try
again with `python -m pip install psutil pywintrace pystray pillow` (the
`python -m pip` form guarantees that you install for the Python that will
run the program).

**Several Pythons on the same PC** — `python` and `py` may point to two
different Pythons, only one of which has the modules: NetGate then starts
with fewer features (no requests, no per-program detail, no icon). The
startup warning and the self-test show the path of the Python actually
used, with the exact installation command to type.

**Nothing connects any more, not even allowed programs** — the
**Autoriser DNS/DHCP** box is not checked in the settings. Without name
resolution, no program knows where to go.

**A VPN no longer connects, protection active** — allow “Noyau de
Windows” (Windows kernel) in the list: some VPNs send their traffic from
the kernel.

**NetGate does not start** — launch it from a *Terminal (Admin)* to see
the error, or open `netgate.log` next to `netgate.py` (or in
`%APPDATA%\NetGate`).

**The banner says “sans détail par programme” (without per-program
detail)** — `pywintrace` is not installed, or the ETW session could not
start (administrator rights refused). The allowance is still measured on
the network adapter; only the per-program detail is missing.

**The banner says “détail par programme : aucun événement reçu”
(per-program detail: no event received)** — the network adapter sees
traffic going through, but per-program listening receives nothing: the
*Consommé* (used) column would stay at zero. The allowance itself stays
accurate. Quit NetGate and run the self-test: its last lines check
per-program metering and, if it fails, query several sources to tell
which one works on this PC.

**The banner says “filtrage : pare-feu Windows (repli)” (filtering:
Windows Firewall, fallback)** — the NetGate engine could not open or
failed; the reason is in the settings (under *Moteur de filtrage*) and in
`netgate.log`. Another NetGate may already be running. To check the engine
on this PC, quit NetGate and run the self-test
(`python netgate.py --test-wfp`, see [Launching](#3-launching)).

**A blocked program still gets through** — with the NetGate engine, this
should not happen: check the banner. With the fallback engine, the program
is probably still *en attente* (pending) and benefits from a permission
that Windows or its installer has set; answer *Bloquer*, and the block rule
overrides all permissions.

**Internet access stayed blocked after a crash** — with the NetGate
engine, this is impossible: its filters disappear with it. With the
fallback engine, restart NetGate (it cleans up its rules at startup), or
click **PANIQUE**. As a last resort, in an administrator PowerShell, the
first command restores the original outbound policy, the second deletes
all `NETGATE_` rules, including the cut-off:

```powershell
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
```

```powershell
Remove-NetFirewallRule -DisplayName "NETGATE_*"
```

**Corrupted configuration** — rename `netgate.state.json` and restart.
NetGate starts again with fresh settings.

---

## 10. License

NetGate is **free software**, distributed under the
**GNU General Public License, version 3 or later** (GPL-3.0-or-later).

Copyright © 2026 ETDEL.

In practice, you may use the program freely, including in a professional
setting, study it, modify it and redistribute it — provided that any
redistributed version, modified or not, remains under the same license,
with its source code and the copyright notice. The program is provided
**without any warranty**: it helps you keep your consumption under
control; it replaces neither your vigilance nor your system's protections.

### Additional terms (section 7)

The GPL v3 lets the author add a few terms (section 7). NetGate's are in the
[`NOTICE`](NOTICE) file, in French and in English:

- **Attribution**: every copy or modified version must keep, visible to the user (an "About"
  window or equivalent) and in its documentation, the notice:

  > NetGate, par ETDEL — https://github.com/theptitprince/NetGate

  A modified version may prefix it with "D'après" (or "Based on") and add its own credits,
  but may neither remove nor hide it.
- **Origin**: a modified version must state clearly that it has been modified, and must not
  present itself as the original or as endorsed by ETDEL.

In NetGate, this notice is shown in the status bar and in the built-in help (F1), *A propos* (about) section.

The full text of the license is in the repository's `LICENSE` file and at
<https://www.gnu.org/licenses/gpl-3.0.html>. The source file
`netgate.py` carries a header that points to `LICENSE` and `NOTICE`.

---

*NetGate — ETDEL 2026 — GPL-3.0-or-later*
