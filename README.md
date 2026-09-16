# NetGate — Contrôle d'accès Internet par application

[![Licence GPL-3.0-or-later](https://img.shields.io/badge/licence-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-3776AB.svg)](https://www.python.org/downloads/)
[![Windows](https://img.shields.io/badge/plateforme-Windows%2010%2F11-0078D6.svg)](#1-installation)

Le robinet Internet est fermé ; vous l'ouvrez programme par programme.
NetGate compte ce que chacun consomme, vous prévient quand l'enveloppe du
jour s'épuise, et ne coupe jamais rien de lui-même.

**À qui ça sert.** À quiconque vit sur une connexion comptée — partage de
connexion mobile, clé 4G, forfait data limité, liaison satellite — où chaque
mégaoctet a de la valeur et où une mise à jour lancée au mauvais moment peut
vider un forfait en une heure. NetGate pilote le pare-feu Windows pour
bloquer tout le trafic sortant, vous demande quoi faire dès qu'un programme
tente de sortir, attribue chaque octet envoyé ou reçu au programme qui l'a
produit, et tient une enveloppe journalière avec alertes à 50, 80 et 100 %.
Il produit une liste d'autorisations qui vous survit d'un lancement à
l'autre, un compteur par programme et par jour, et un blason dans la zone
de notification qui se remplit avec votre consommation. Version actuelle :
1.3.

Python 3.8+ avec tkinter, `psutil`, `pywintrace`, `pystray` et `pillow` —
Windows 10 ou 11, droits administrateur.

---

## 1. Installation

### Python

Il faut **Python 3.8 ou plus récent**, avec **tkinter**.

Installez Python depuis <https://www.python.org/downloads/> et **cochez
deux cases** dans l'installateur :

- `Add Python to PATH` (sur le premier écran)
- `tcl/tk and IDLE` (sur l'écran « Optional Features »)

Sans la seconde, l'application ne peut pas s'ouvrir : tkinter est ce qui
dessine toute l'interface.

Pour vérifier, ouvrez PowerShell et tapez :

```powershell
python --version
python -m tkinter
```

La première commande doit afficher un numéro de version, la seconde doit
ouvrir une petite fenêtre de test.

### Les bibliothèques

```powershell
python -m pip install psutil pywintrace pystray pillow
```

Chacune est facultative au sens strict : NetGate démarre même si l'une
manque, avec des fonctions en moins. Le tableau dit lesquelles, pour que
vous puissiez décider en connaissance de cause.

| Bibliothèque | Ce qu'elle apporte | Sans elle |
|---|---|---|
| `psutil` | découverte des connexions ouvertes, comptage de repli | aucun programme n'est détecté, aucune notification n'apparaît |
| `pywintrace` | comptage par programme (Event Tracing for Windows) | le compteur affiche un total « global estimé », sans détail par programme |
| `pystray` + `pillow` | l'icône dans la zone de notification et son menu | la fenêtre principale reste seule, sans blason près de l'horloge |

### Les droits administrateur

Modifier le pare-feu Windows exige l'élévation : NetGate la demande lui-même
au lancement (invite UAC). Si vous la refusez, il propose un **mode
limité** où l'interface et les compteurs fonctionnent, mais où rien n'est
bloqué. C'est un bon mode pour observer avant de décider.

---

## 2. Les fichiers

Récupérez le dépôt, au choix :

- bouton vert **Code → Download ZIP** sur la page GitHub, puis décompressez
  l'archive dans un dossier (par exemple `C:\NetGate`) ;
- ou, si vous avez git :

```powershell
git clone https://github.com/theptitprince/NetGate.git C:\NetGate
```

Le programme tient en **un seul fichier**, `netgate.py`, organisé en
sections :

| Section | Rôle |
|---|---|
| `Firewall` | génère et exécute les scripts `netsh advfirewall` |
| `EtwMeter` | écoute le fournisseur Kernel-Network et attribue les octets à chaque processus |
| `ConnScanner` | découvre les connexions ouvertes et signale les programmes sans décision |
| `State` | charge et sauvegarde le fichier d'état, gère les périodes et les profils |
| `Inspector` | répond à « qui est ce programme ? » |
| `AuthToast` | la carte Autoriser / Bloquer / Plus tard |
| `Tray` | l'icône de la zone de notification et son menu |
| `NetGateApp` | la fenêtre principale, les réglages, la liste, les plages horaires |

Le fichier `LICENSE` contient le texte de la licence du programme (voir
« Licence » en fin de document).

Placez `netgate.py` **dans son propre dossier** : il y crée ses fichiers de
travail (voir « Ce que le programme crée à côté de lui »).

---

## 3. Lancement

Ouvrez PowerShell dans le dossier du programme et tapez :

```powershell
python netgate.py
```

Windows demande les droits administrateur : acceptez. La fenêtre principale
s'ouvre, et un blason apparaît dans la zone de notification, à côté de
l'horloge.

Un raccourci sur le bureau est pratique : cible
`python C:\NetGate\netgate.py`, dossier de démarrage `C:\NetGate`. Pour
lancer NetGate sans fenêtre de console, remplacez `python` par `pythonw`.

**Fermer la fenêtre ne quitte pas** : NetGate continue de surveiller et le
blocage reste actif. Pour arrêter le programme, passez par le menu de
l'icône (*Quitter*). À ce moment, toutes les règles créées sont supprimées
et le pare-feu retrouve sa politique sortante d'origine. Ce détour est
volontaire : une fermeture par mégarde ne doit jamais couper la surveillance
en laissant croire qu'elle tourne.

---

## 4. Prise en main

Le premier réflexe utile est d'**observer avant de bloquer**. Laissez
NetGate tourner une heure ou deux **protection inactive** : il découvre les
programmes qui sortent, compte ce qu'ils consomment et retient vos réponses,
sans rien couper. Vous voyez ainsi qui consomme quoi sans risquer de casser
une session de travail.

Ensuite :

1. **Réglages** : enveloppe du jour (en Mo), heure de remise à zéro, et la
   case *DNS/DHCP essentiels*, à laisser cochée.
2. **Activer la protection.**
3. Ouvrez votre navigateur : une carte apparaît en bas à droite, cliquez
   *Autoriser*.
4. Répétez pour chaque programme dont vous avez besoin. Au bout de dix
   minutes, les demandes s'espacent : la liste est constituée.

Chaque carte de demande affiche le nom lisible du programme, son éditeur, à
quoi il sert et un conseil, pour que vous n'ayez pas à deviner ce que cache
`svchost.exe` ou `msedgewebview2.exe`. Trois réponses : *Autoriser*,
*Bloquer*, *Plus tard*. La dernière laisse la question ouverte sans rien
changer.

---

## 5. Comment ça marche

NetGate n'est pas un pare-feu : il pilote **le pare-feu Windows** existant
via `netsh advfirewall`. C'est ce qui le rend léger et prévisible : ce que
vous voyez dans *Pare-feu Windows Defender avec fonctions avancées de
sécurité* → *Règles de trafic sortant* est exactement ce qui s'applique.

**Le blocage.** Quand la protection est active, la politique sortante des
trois profils réseau (domaine, privé, public) passe à *bloquer*, puis une
règle *autoriser* est créée par programme accepté. Toutes les règles de
NetGate portent le préfixe `NETGATE_` ; les règles tierces ne sont jamais
touchées. Les modifications sont regroupées dans un script `netsh -f`
exécuté en une fois, parce que chaque appel `netsh` isolé coûte environ
200 ms et figerait l'interface.

**La règle DNS/DHCP « essentiels ».** Une règle facultative, cochée par
défaut, laisse passer `svchost.exe` sur les ports 53 (DNS) et 67-68 (DHCP).
Sans elle, même les programmes autorisés ne résolvent plus aucun nom et
tout semble bloqué. Si tout se met à échouer, c'est le premier réglage à
vérifier.

**Le comptage.** NetGate s'abonne au fournisseur
`Microsoft-Windows-Kernel-Network` (Event Tracing for Windows) pour
attribuer chaque octet envoyé ou reçu au processus qui l'a produit. Si
`pywintrace` manque ou si la session ETW ne peut pas démarrer, il se replie
sur un total global mesuré par `psutil.net_io_counters()`, signalé comme
« global estimé » pour que vous sachiez que le détail par programme n'est
pas disponible.

**La découverte.** Toutes les 1,5 s, la liste des connexions ouvertes est
relevée et chaque exécutable qui n'a pas encore reçu de décision déclenche
une carte de demande.

**L'inspecteur.** Pour répondre à « qui est ce programme ? », NetGate
combine un glossaire en français des processus courants, la version et
l'éditeur lus dans les ressources du fichier, la signature numérique, le
titre de fenêtre, et pour `svchost.exe` le service Windows exact hébergé par
ce processus.

**La remise en état.** Au démarrage, NetGate supprime les règles `NETGATE_`
restées d'une session interrompue (coupure de courant, processus tué), pour
que rien ne reste bloqué à votre insu. Le bouton **PANIQUE** fait la même
chose à la demande, immédiatement : toutes les règles disparaissent et
Internet revient.

---

## 6. Ce que le programme crée à côté de lui

Tout est rangé **à côté de `netgate.py`**. Si ce dossier n'est pas
inscriptible (Program Files, clé USB protégée, dossier réseau), NetGate se
replie automatiquement sur `%APPDATA%\NetGate`.

| Fichier | Contenu |
|---|---|
| `netgate.state.json` | réglages, profils, autorisations, compteurs du jour, historique, catalogue des programmes vus. **Copiez-le pour sauvegarder votre configuration.** Renommez-le pour repartir de zéro. |
| `netgate.log` | trace de démarrage et erreurs éventuelles : le premier fichier à ouvrir quand quelque chose ne va pas. |
| `netgate.ico` | le blason, régénéré à chaque changement de profil ou de palier de consommation, pour la fenêtre et l'exécutable. |

`netgate.state.json` contient les chemins de vos programmes : c'est un
fichier personnel, ne le partagez pas tel quel.

---

## 7. L'enveloppe, les plages horaires, les profils

### La liste des programmes

Vert = autorisé, rouge = bloqué, orange = en attente. Les colonnes se trient
(accès, volume), un double-clic change la décision, et la fiche descriptive
en bas de fenêtre rappelle qui est le programme sélectionné. *Ajouter un
programme* autorise quelque chose à l'avance, sans attendre qu'il se
manifeste — utile pour un logiciel de visioconférence juste avant une
réunion.

### L'enveloppe du jour

- L'enveloppe n'est **décomptée que lorsque la protection est active**.
  Hors protection, le trafic est mesuré et affiché à part : observer ne
  coûte rien sur le quota.
- La remise à zéro se fait à l'heure choisie, à la minute près, en heure
  locale ou UTC. Si l'ordinateur est éteint à ce moment-là, la bascule se
  fait au démarrage suivant ; si l'horloge du système a reculé, la bascule
  est forcée pour ne pas prolonger indûment la journée.
- Alertes à 50, 80 et 100 % : NetGate prévient, il ne coupe jamais. Couper
  serait décider à votre place ; la décision reste la vôtre.
- *Remettre le compteur à zéro*, dans les réglages, repart de zéro sans
  toucher aux autorisations.

### Les plages horaires

Réglages → *Plages horaires* : un tableau de 48 demi-heures à cocher. Hors
plage, plus rien ne sort, même les programmes autorisés. Raccourcis *tout
ouvrir*, *tout fermer*, *08h-22h*. Le bandeau indique la prochaine ouverture
ou fermeture, pour que vous ne cherchiez pas pourquoi tout s'est arrêté à
22 h.

### L'icône près de l'horloge

Le blason se remplit avec la consommation (vert → orange → rouge). Clic
droit : *Ouvrir*, choix du profil, Mo restants, *Tout débloquer (PANIQUE)*,
*Quitter*.

### Les profils

Par défaut, une seule liste d'autorisations, et aucune barre de profils
n'encombre la fenêtre. Si vous créez des profils dans les réglages, une
barre de choix apparaît en haut. Modèles proposés : *Blackout*, *Essentiel*,
*Travail*, *Visio*, chacun avec sa couleur et son budget indicatif. Un
profil est une liste d'autorisations complète : basculer de *Travail* à
*Visio* remplace l'une par l'autre.

### Effacer et recommencer

Les réglages permettent de réinitialiser la liste active, les compteurs,
l'historique, les autorisations, ou de tout remettre à neuf. Les règles du
pare-feu sont nettoyées avant chaque réinitialisation, pour qu'aucun
programme ne reste bloqué sans moyen de le débloquer.

### L'aide intégrée

La touche **F1** ouvre une aide en français qui reprend tout ce qui précède,
directement dans le programme.

---

## 8. Construire un exécutable

Un exécutable autonome évite d'installer Python sur la machine cible et
demande lui-même l'élévation UAC. Depuis le dossier des sources :

```powershell
python -m pip install --upgrade pyinstaller psutil pywintrace pystray pillow
```

```powershell
python -c "import netgate; netgate.write_ico(netgate.C_ACCENT, 0.35)"
```

```powershell
python -m PyInstaller --onefile --noconsole --uac-admin --clean --noconfirm --name NetGate --icon netgate.ico --collect-all etw --collect-all pystray --hidden-import pystray._win32 --hidden-import PIL._tkinter_finder netgate.py
```

- `--onefile --noconsole` : un seul fichier, sans fenêtre de console.
- `--uac-admin` : l'exécutable demande l'élévation au lancement.
- `--icon netgate.ico` : le blason, généré par la deuxième commande.
- `--collect-all` / `--hidden-import` : modules chargés dynamiquement que
  PyInstaller ne détecte pas seul.

Comptez 2 à 5 minutes. Résultat : `dist\NetGate.exe`, autonome, d'environ
30 Mo, à placer dans son propre dossier comme `netgate.py`. Les dossiers
`build/`, `dist/` et le fichier `NetGate.spec` peuvent ensuite être
supprimés. Au premier lancement, SmartScreen peut afficher un avertissement
(programme non signé) : *Informations complémentaires* → *Exécuter quand
même*.

Un antivirus trop zélé peut bloquer PyInstaller : c'est la cause la plus
fréquente d'échec.

---

## 9. En cas de souci

**« No module named tkinter »** — Python a été installé sans tcl/tk.
Relancez l'installateur, choisissez *Modify*, et cochez `tcl/tk and IDLE`.

**« No module named psutil »** (ou `etw`, `pystray`, `PIL`) — la commande
d'installation n'a pas été exécutée, ou l'a été pour un autre Python.
Réessayez avec `python -m pip install psutil pywintrace pystray pillow` (la
forme `python -m pip` garantit qu'on installe bien pour le Python qui
lancera le programme).

**Plus rien ne se connecte, même les programmes autorisés** — la case
**DNS/DHCP essentiels** n'est pas cochée dans les réglages. Sans résolution
de noms, aucun programme ne sait où aller.

**NetGate ne démarre pas** — lancez-le depuis un *Terminal (administrateur)*
pour voir l'erreur, ou ouvrez `netgate.log` à côté de `netgate.py` (ou dans
`%APPDATA%\NetGate`).

**Le compteur indique « global estimé »** — `pywintrace` n'est pas installé
ou la session ETW n'a pas pu démarrer. Le total reste juste, le détail par
programme n'est pas disponible.

**Internet est resté bloqué après un plantage** — relancez NetGate (il
nettoie ses règles au démarrage), ou cliquez **PANIQUE**. En dernier
recours, dans un PowerShell administrateur :

```powershell
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
```

**Configuration corrompue** — renommez `netgate.state.json` et relancez.
NetGate repart avec des réglages neufs.

---

## 10. Licence

NetGate est un **logiciel libre**, distribué sous la licence
**GNU General Public License, version 3 ou ultérieure** (GPL-3.0-or-later).

Copyright © 2026 ETDEL.

Concrètement, vous pouvez utiliser le programme librement, y compris dans un
cadre professionnel, l'étudier, le modifier et le redistribuer — à condition
que toute version redistribuée, modifiée ou non, reste sous la même licence,
avec son code source et la mention de copyright. Le programme est fourni
**sans aucune garantie** : il vous aide à maîtriser votre consommation, il
ne remplace ni votre vigilance ni les protections de votre système.

Le texte intégral de la licence est dans le fichier `LICENSE` du dépôt et
sur <https://www.gnu.org/licenses/gpl-3.0.html>. Le fichier source
`netgate.py` porte l'en-tête de licence correspondant.

---

*NetGate — ETDEL 2026 — GPL-3.0-or-later*
