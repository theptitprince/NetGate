# NetGate — Contrôle d'accès Internet par application

[![Licence GPL-3.0-or-later](https://img.shields.io/badge/licence-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-3776AB.svg)](https://www.python.org/downloads/)
[![Windows](https://img.shields.io/badge/plateforme-Windows%2010%2F11-0078D6.svg)](#1-installation)

Le robinet Internet est fermé ; vous l'ouvrez programme par programme.
NetGate compte ce que chacun consomme, vous prévient quand l'enveloppe du
jour s'épuise, et coupe Internet quand elle est vide.

**À qui ça sert.** À quiconque vit sur une connexion comptée — partage de
connexion mobile, clé 4G, forfait data limité, liaison satellite — où chaque
mégaoctet a de la valeur et où une mise à jour lancée au mauvais moment peut
vider un forfait en une heure. NetGate pose ses propres filtres dans le
moteur de filtrage de Windows pour bloquer tout ce que vous n'avez pas
autorisé, vous demande quoi faire dès qu'un programme tente de sortir,
mesure l'enveloppe sur la carte réseau par laquelle passent les données,
attribue à chaque programme ce qu'il échange avec Internet, et tient une
enveloppe journalière avec alertes à 50, 80 et 100 % et coupure à 100 %.
Il produit une liste d'autorisations qui vous survit d'un lancement à
l'autre, un compteur par programme et par jour, et un blason dans la zone
de notification qui se remplit avec votre consommation. Version actuelle :
2.0.

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
| `psutil` | découverte des connexions ouvertes, adresses des cartes réseau | aucun programme n'est détecté, aucune notification n'apparaît |
| `pywintrace` | comptage par programme (Event Tracing for Windows) | l'enveloppe reste mesurée sur la carte réseau, sans détail par programme |
| `pystray` + `pillow` | l'icône dans la zone de notification et son menu | la fenêtre principale reste seule, sans blason près de l'horloge |

### Les droits administrateur

Filtrer les connexions exige l'élévation : NetGate la demande lui-même au
lancement (invite UAC). Si vous la refusez, il propose un **mode
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
| `WfpEngine` | la session dynamique dans le moteur de filtrage de Windows (WFP) : sous-couche, filtres, transactions |
| `wfp_specs`, `WfpBackend` | traduisent la liste d'autorisations en filtres NetGate et n'appliquent que les différences |
| `Firewall`, `NetshBackend` | le moteur de repli : des règles du pare-feu Windows posées par `netsh advfirewall` |
| `EtwMeter` | écoute le fournisseur Kernel-Network et attribue à chaque processus ses octets échangés avec Internet ; repère les connexions refusées |
| `NicMeter` | lit les compteurs des cartes réseau : la mesure de l'enveloppe |
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
l'icône (*Quitter*). À ce moment, tous les filtres de NetGate disparaissent
et Internet redevient normal. Ce détour est volontaire : une fermeture par
mégarde ne doit jamais couper la surveillance en laissant croire qu'elle
tourne.

**Vérifier le moteur, une fois.** Avant la première utilisation sur un PC,
NetGate fermé, lancez l'autotest :

```powershell
python netgate.py --test-wfp
```

Il demande les droits administrateur, vérifie en une quinzaine de secondes
que le moteur de filtrage fonctionne sur ce PC, et laisse un rapport
`netgate-test-wfp.txt`. Il ne touche à rien d'autre qu'à lui-même : ses
filtres de test ne visent que sa propre connexion vers une adresse de
documentation (`192.0.2.1`, inexistante sur Internet) ou vers localhost, et
disparaissent à la fin. Avec l'exécutable : `NetGate.exe --test-wfp`.

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
*Bloquer*, *Plus tard*. La dernière laisse la question ouverte ; en
attendant, le programme reste bloqué. Une carte marquée *Connexion bloquée*
signale un programme qui vient d'essayer de sortir et a été refusé :
autorisez-le, il réessaie de lui-même.

---

## 5. Comment ça marche

Depuis Windows Vista, tout pare-feu sous Windows, celui de Microsoft
compris, pose ses filtres dans un même moteur : la **Windows Filtering
Platform** (WFP). NetGate 2 y pose les siens directement, comme le font les
pare-feu applicatifs à la ZoneAlarm, sans pilote à installer et sans toucher
aux règles du pare-feu Windows.

**Le blocage.** Quand la protection est active, NetGate ouvre une session
dans le moteur et y crée sa propre sous-couche, de priorité maximale. Dans
cette sous-couche, le filtre de plus fort poids qui correspond décide :
localhost ouvert, puis réseau local ouvert, puis la coupure (enveloppe
épuisée, hors plage horaire), puis un filtre *autoriser* par programme
accepté, et enfin *tout le reste est bloqué*. Les programmes refusés ou
encore en attente n'ont pas de filtre à eux : le blocage général s'applique.
Chaque changement est appliqué d'un bloc, dans une transaction, et ne touche
que les filtres qui changent.

**Pourquoi un moteur à soi.** Windows et de nombreux logiciels posent leurs
propres règles *autoriser* dans le pare-feu Windows : applications du
Store, services Windows, certains installateurs (plus d'une centaine sur un
poste courant). Dans le pare-feu Windows, elles laissent passer leur
programme malgré une politique *bloquer*. Dans le moteur, un blocage de la
sous-couche NetGate est définitif : aucune de ces autorisations ne passe
devant. *Bloquer* veut vraiment dire bloqué, et un programme en attente de
réponse est bloqué lui aussi.

**La session dynamique.** Les filtres de NetGate appartiennent à une session
que Windows supprime dès que NetGate s'arrête, qu'il quitte normalement,
plante ou soit tué. Rien ne peut rester bloqué à votre insu, et aucun
nettoyage n'est nécessaire au démarrage suivant.

**La règle DNS/DHCP « essentiels ».** Un filtre facultatif, coché par
défaut, laisse passer `svchost.exe` vers les ports 53 (DNS), 67 et 547
(DHCP). Sans lui, même les programmes autorisés ne résolvent plus aucun nom
quand le serveur DNS est sur Internet (fréquent en 4G), et un modem en mode
pont ne renouvelle plus l'adresse du PC. Si tout se met à échouer, c'est le
premier réglage à vérifier.

**Le moteur de repli.** Si le moteur NetGate ne peut pas s'ouvrir, ou s'il
échoue en cours de route, NetGate bascule sur le moteur de la version 1 :
des règles du pare-feu Windows posées par `netsh advfirewall`, toutes
préfixées `NETGATE_`. La politique sortante passe à *bloquer*, une règle
*autoriser* est créée par programme accepté et une règle *bloquer* par
programme refusé ; une règle de blocage l'emporte sur toutes les
autorisations de Windows. Ces règles survivent à NetGate : elles sont
retirées en quittant, et au démarrage suivant après un arrêt brutal.
Réglages → *Moteur de filtrage* pour choisir ce moteur ; le bandeau indique
le moteur en service.

**Le comptage de l'enveloppe.** L'enveloppe est mesurée sur la carte
réseau par laquelle passent les données (Wi-Fi, Ethernet, clé 4G, partage
de connexion USB ou Bluetooth), avec les compteurs que montre le
Gestionnaire des tâches : c'est la mesure la plus proche de celle de
l'opérateur, en-têtes compris, trafic des machines virtuelles compris. Ce
qui reste dans le PC n'y passe pas : un serveur WAMP, MySQL ou PHP
interrogé en localhost ne coûte rien. Le trafic avec le réseau local (NAS,
imprimante, autre PC) est retiré du compte. Les cartes virtuelles (tunnel
VPN, VirtualBox, Hyper-V) ne sont pas comptées : elles relaient un trafic
qui sort ensuite par la carte physique, les compter le décompterait deux
fois. Réglages → *Cartes décomptées* pour changer ce choix.

**Le détail par programme.** NetGate s'abonne au fournisseur
`Microsoft-Windows-Kernel-Network` (Event Tracing for Windows) pour
attribuer à chaque processus les octets qu'il échange avec Internet ;
chaque événement porte les deux adresses de la connexion, ce qui permet
d'écarter localhost et le réseau local. Si `pywintrace` manque ou si la
session ETW ne peut pas démarrer, l'enveloppe reste mesurée sur la carte,
sans détail par programme. Avec un VPN, le programme et le VPN comptent
chacun leur part : la somme de la liste peut dépasser l'enveloppe, qui
reste juste.

**La découverte.** Toutes les 1,5 s, la liste des connexions ouvertes vers
Internet est relevée et chaque exécutable qui n'a pas encore reçu de
décision déclenche une carte de demande. Un programme bloqué, lui, n'a
jamais de connexion ouverte : NetGate écoute donc aussi l'événement 1020 du
fournisseur `Microsoft-Windows-TCPIP`, « connexion refusée par le moteur de
filtrage », qui donne le processus et l'adresse visée. La carte apparaît
alors avec la mention *Connexion bloquée* ; autorisez, et le programme
réessaie de lui-même. Un programme qui ne parle qu'à localhost ou au
réseau local ne déclenche rien.

**Les mises à jour.** Beaucoup de programmes changent de dossier à chaque
version (`claude_2.110…`, `app-1.0.9187`, `152.0.4191.66`). NetGate les
reconnaît : une seule ligne dans la liste, dont l'emplacement porte `*` à
la place du numéro de version, et la décision suit la nouvelle version,
règle du pare-feu comprise, sans reposer la question.

**L'inspecteur.** Pour répondre à « qui est ce programme ? », NetGate
combine un glossaire en français des processus courants, la version et
l'éditeur lus dans les ressources du fichier, la signature numérique, le
titre de fenêtre, et pour `svchost.exe` le service Windows exact hébergé par
ce processus.

**La remise en état.** Le bouton **PANIQUE** ferme la session NetGate :
tous les filtres disparaissent immédiatement et Internet revient. Si la
session précédente utilisait le moteur de repli et s'est interrompue
(coupure de courant, processus tué), NetGate retire au démarrage les règles
`NETGATE_` restées dans le pare-feu Windows.

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
| `netgate-test-wfp.txt` | le rapport du dernier autotest du moteur (`--test-wfp`). |
| `netgate.state.json.v2.bak` | copie de l'état tel qu'il était avant sa conversion par la version 1.4 ; supprimable une fois la 1.4 validée. |

`netgate.state.json` contient les chemins de vos programmes : c'est un
fichier personnel, ne le partagez pas tel quel.

---

## 7. L'enveloppe, les plages horaires, les profils

### La liste des programmes

Vert = autorisé, rouge = bloqué, orange = en attente. Les colonnes se trient
(accès, volume), un double-clic change la décision, et la fiche descriptive
en bas de fenêtre rappelle qui est le programme sélectionné. La colonne
*Fichier* montre l'exécutable : `firefox.exe` et `pingsender.exe` sont deux
programmes distincts du même logiciel, chacun avec sa décision. *Ajouter un
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
- Alertes à 50, 80 et 100 %. À 100 %, **Internet est coupé** jusqu'à la
  remise à zéro : une seule règle de blocage vers toutes les adresses
  Internet, qui passe devant toutes les autorisations, celles de NetGate
  comme celles déjà posées dans Windows. Localhost et le réseau local
  restent ouverts. La coupure intervient dans la seconde ; quelques Mo
  peuvent encore passer pendant ce délai.
- *Rallonge pour aujourd'hui*, dans le bandeau ou le menu de l'icône
  pendant la coupure, ajoute des Mo pour la période en cours seulement :
  le réglage de l'enveloppe ne change pas.
- Pour être seulement prévenu, sans coupure : Réglages → décocher *Couper
  Internet quand l'enveloppe est épuisée*.
- *Remettre le compteur à zéro*, dans les réglages, repart de zéro sans
  toucher aux autorisations.

### Les plages horaires

Réglages → *Plages horaires* : un tableau de 48 demi-heures à cocher. Hors
plage, plus rien ne sort vers Internet, même les programmes autorisés, quel
que soit le profil ; localhost et le réseau local restent ouverts.
Raccourcis *tout ouvrir*, *tout fermer*, *08h-22h*. Le bandeau indique la
prochaine ouverture ou fermeture, pour que vous ne cherchiez pas pourquoi
tout s'est arrêté à 22 h.

### L'icône près de l'horloge

Le blason se remplit avec la consommation (vert → orange → rouge). Clic
droit : *Ouvrir*, choix du profil, Mo restants, *Rallonge* pendant une
coupure, *Tout débloquer (PANIQUE)*, *Quitter*.

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

**Plusieurs Python sur le même PC** — `python` et `py` peuvent désigner deux
Python différents, dont un seul a les modules : NetGate démarre alors avec
des fonctions en moins (pas de demandes, pas de détail par programme, pas
d'icône). L'avertissement de démarrage et l'autotest affichent le chemin du
Python réellement utilisé, avec la commande d'installation exacte à taper.

**Plus rien ne se connecte, même les programmes autorisés** — la case
**DNS/DHCP essentiels** n'est pas cochée dans les réglages. Sans résolution
de noms, aucun programme ne sait où aller.

**NetGate ne démarre pas** — lancez-le depuis un *Terminal (administrateur)*
pour voir l'erreur, ou ouvrez `netgate.log` à côté de `netgate.py` (ou dans
`%APPDATA%\NetGate`).

**Le bandeau indique « sans détail par programme »** — `pywintrace` n'est
pas installé, ou la session ETW n'a pas pu démarrer (droits administrateur
refusés). L'enveloppe reste mesurée sur la carte réseau ; seul le détail
par programme manque.

**Le bandeau indique « filtrage : pare-feu Windows (repli) »** — le moteur
NetGate n'a pas pu s'ouvrir ou a échoué ; la raison est dans les réglages
(sous *Moteur de filtrage*) et dans `netgate.log`. Un autre NetGate tourne
peut-être déjà. Pour vérifier le moteur sur ce PC, quittez NetGate et
lancez l'autotest (`python netgate.py --test-wfp`, voir « Lancement »).

**Un programme bloqué passe quand même** — avec le moteur NetGate, cela ne
devrait pas arriver : vérifiez le bandeau. Avec le moteur de repli, le
programme est sans doute encore *en attente* et profite d'une autorisation
que Windows ou son installateur a posée ; répondez *Bloquer*, la règle de
blocage l'emporte sur toutes les autorisations.

**Internet est resté bloqué après un plantage** — avec le moteur NetGate,
c'est impossible : ses filtres disparaissent avec lui. Avec le moteur de
repli, relancez NetGate (il nettoie ses règles au démarrage), ou cliquez
**PANIQUE**. En dernier recours, dans un PowerShell administrateur, la
première commande rétablit la politique sortante d'origine, la seconde
supprime toutes les règles `NETGATE_`, dont la coupure :

```powershell
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
```

```powershell
Remove-NetFirewallRule -DisplayName "NETGATE_*"
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
