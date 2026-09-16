# NetGate

**Contrôle d'accès Internet par application, pour Windows.**

Le robinet Internet est fermé ; tu l'ouvres programme par programme. NetGate compte ce que chacun consomme, te prévient quand l'enveloppe du jour s'épuise, et ne coupe jamais rien de lui-même.

Pensé pour les connexions comptées (partage de connexion mobile, forfait data limité, satellite, clé 4G) où chaque mégaoctet a de la valeur et où un Windows Update lancé au mauvais moment peut vider un forfait en une heure.

---

## Sommaire

- [Ce que fait NetGate](#ce-que-fait-netgate)
- [Comment ça marche](#comment-ça-marche)
- [Installation](#installation)
  - [Option A : l'exécutable](#option-a--lexécutable)
  - [Option B : depuis les sources](#option-b--depuis-les-sources)
- [Premier démarrage](#premier-démarrage)
- [Fonctionnalités](#fonctionnalités)
- [Construire l'exécutable](#construire-lexécutable)
- [Fichiers et données](#fichiers-et-données)
- [Dépannage](#dépannage)
- [Structure du code](#structure-du-code)
- [Historique des versions](#historique-des-versions)
- [Licence](#licence)

---

## Ce que fait NetGate

- **Bloque tout le trafic sortant par défaut**, puis autorise les programmes un par un.
- **Te demande** dès qu'un programme inconnu essaie de sortir : une carte apparaît en bas à droite avec son nom lisible, son éditeur, à quoi il sert, et un conseil. Trois réponses : *Autoriser*, *Bloquer*, *Plus tard*.
- **Mesure la consommation** de chaque programme (Mo envoyés / reçus) en temps réel.
- **Surveille une enveloppe journalière** (ex. 400 Mo/jour) avec alertes à 50, 80 et 100 %, remise à zéro à l'heure de ton choix, heure locale ou UTC.
- **Plages horaires** : un tableau de 48 demi-heures, hors plage plus rien ne sort.
- **Vit dans la zone de notification** : le blason se remplit avec ta consommation (vert → orange → rouge).
- **Bouton PANIQUE** : rétablit Internet immédiatement, en supprimant toutes les règles.
- **Profils facultatifs** (Travail, Visio, Blackout, Essentiel…) pour basculer d'un usage à l'autre.
- **Aide intégrée** (touche F1) qui explique tout ce qui précède, en français.

---

## Comment ça marche

NetGate ne réinvente pas de pare-feu : il pilote **le pare-feu Windows** existant via `netsh advfirewall`.

| Composant | Rôle |
|---|---|
| **Pare-feu** (`Firewall`) | Passe la politique sortante des trois profils réseau à *block*, puis crée une règle `allow` par programme autorisé. Toutes les règles portent le préfixe `NETGATE_` ; les règles tierces ne sont jamais touchées. Les modifications sont regroupées dans un script `netsh -f` pour ne pas figer l'interface. |
| **Compteur ETW** (`EtwMeter`) | S'abonne au fournisseur `Microsoft-Windows-Kernel-Network` (Event Tracing for Windows) pour attribuer chaque octet envoyé/reçu à un PID. Si `pywintrace` est absent ou indisponible, repli sur un comptage global estimé via `psutil.net_io_counters()`. |
| **Détecteur** (`ConnScanner`) | Toutes les 1,5 s, liste les connexions ouvertes (`psutil`) et signale les exécutables qui n'ont pas encore reçu de décision. |
| **Inspecteur** (`Inspector`) | Répond à *« c'est quoi, ce programme ? »* : glossaire français des processus courants, version/éditeur lus dans les ressources du fichier, signature numérique, titre de fenêtre, et pour `svchost.exe` le service Windows exact hébergé par ce PID. |
| **Interface** (`NetGateApp`, `AuthToast`, `Tray`) | Fenêtre principale Tkinter (thème sombre), carte de notification en bas à droite, icône de zone de notification avec menu contextuel. |
| **État** (`State`) | Un seul fichier JSON : réglages, profils, autorisations, compteurs du jour, historique. |

**Règle DNS/DHCP « essentiels »** : quand la protection est active, une règle facultative laisse passer `svchost.exe` sur les ports 53 (DNS) et 67-68 (DHCP). Sans elle, même les programmes autorisés ne résolvent plus aucun nom.

**Sortie propre** : *Quitter* depuis le menu de l'icône supprime toutes les règles `NETGATE_` et remet la politique sortante à *allow*. Si NetGate est tué brutalement, les règles restent dans Windows : relance NetGate (qui nettoie au démarrage) ou utilise PANIQUE.

---

## Installation

### Prérequis

- **Windows 10 ou 11**. NetGate refuse de démarrer sur un autre système.
- **Droits administrateur** : indispensables pour modifier le pare-feu. NetGate demande l'élévation UAC au lancement. Sans élévation, un *mode limité* reste possible : l'interface et les compteurs fonctionnent, le blocage non.

### Option A : l'exécutable

1. Télécharge `NetGate.exe` depuis la page **Releases** de ce dépôt.
2. Place-le **dans son propre dossier** (il y créera `netgate.state.json` et `netgate.log`).
3. Double-clique. Windows demande les droits administrateur : c'est normal.
4. Au premier lancement, SmartScreen peut afficher un avertissement (programme non signé) : *Informations complémentaires* → *Exécuter quand même*.

Aucune installation de Python n'est nécessaire.

### Option B : depuis les sources

```bash
pip install psutil pywintrace pystray pillow
```

Puis, dans un terminal **administrateur** :

```bash
python netgate.py
```

Toutes les dépendances sont optionnelles au sens strict : NetGate démarre même si l'une manque, avec des fonctions dégradées.

| Dépendance | Sans elle |
|---|---|
| `psutil` | Pas de détection des connexions, pas de comptage de repli. |
| `pywintrace` | Comptage par processus impossible ; affichage « global estimé ». |
| `pystray` + `pillow` | Pas d'icône dans la zone de notification. |

`tkinter` est fourni avec Python pour Windows.

---

## Premier démarrage

1. **Réglages** : enveloppe du jour (Mo), heure de remise à zéro, case DNS/DHCP (à laisser cochée).
2. **Activer la protection.**
3. Ouvre ton navigateur : une notification apparaît, clique *Autoriser*.
4. Répète pour chaque programme dont tu as besoin. Au bout de dix minutes, tu n'es plus dérangé.

> Conseil : laisse d'abord NetGate tourner **protection inactive** pendant une heure ou deux. Il observe, compte et retient tes réponses sans rien bloquer, ce qui permet de découvrir qui consomme quoi sans rien casser.

---

## Fonctionnalités

### La liste des applications

Vert = autorisé, rouge = bloqué, orange = en attente. Tri par colonne (accès, volume), double-clic pour changer d'avis, fiche descriptive en bas de fenêtre. *Ajouter un programme* autorise quelque chose à l'avance, sans attendre qu'il se manifeste.

### L'enveloppe

- Décomptée **uniquement quand la protection est active** ; hors protection, le trafic est mesuré mais affiché à part.
- Remise à zéro à l'heure choisie (à la minute près, heure locale ou UTC), **même si le PC était éteint** à ce moment-là.
- Alertes à 50, 80 et 100 % : NetGate prévient, mais ne coupe jamais.
- Bouton *Remettre le compteur à zéro* dans les réglages, sans toucher aux autorisations.

### Les plages horaires

Réglages → *Plages horaires* : 48 demi-heures à cocher. Hors plage, plus rien ne sort, même les programmes autorisés. Raccourcis *tout ouvrir*, *tout fermer*, *08h-22h*. Le bandeau indique la prochaine ouverture ou fermeture.

### L'icône près de l'horloge

- La croix de la fenêtre **ne quitte pas** : NetGate continue de surveiller et le blocage reste actif.
- Clic droit : *Ouvrir*, choix du profil, Mo restants, *Tout débloquer (PANIQUE)*, *Quitter*.
- Le blason se remplit avec la consommation.

### Les profils

Par défaut, une seule liste d'autorisations. Si tu crées des profils dans les réglages, une barre de choix apparaît en haut de la fenêtre. Modèles proposés : *Blackout*, *Essentiel*, *Travail*, *Visio*, chacun avec sa couleur et son budget indicatif.

### Effacer et recommencer

Les réglages permettent de réinitialiser la liste active, les compteurs, l'historique, les autorisations, ou tout remettre à neuf. Les règles du pare-feu sont nettoyées avant, pour qu'aucun programme ne reste bloqué sans moyen de le débloquer.

---

## Construire l'exécutable

Depuis le dossier des sources, avec Python installé :

```bash
pip install --upgrade pyinstaller psutil pywintrace pystray pillow
```

```bash
python -m PyInstaller --onefile --noconsole --uac-admin --clean --noconfirm --name NetGate --icon netgate.ico --collect-all etw --collect-all pystray --hidden-import pystray._win32 --hidden-import PIL._tkinter_finder netgate.py
```

- `--onefile --noconsole` : un seul fichier, sans fenêtre de console.
- `--uac-admin` : l'exécutable demande lui-même l'élévation UAC au lancement.
- `--icon netgate.ico` : le blason fourni dans ce dépôt (régénérable avec `python -c "import netgate; netgate.write_ico(netgate.C_ACCENT, 0.35)"`).
- `--collect-all` / `--hidden-import` : modules chargés dynamiquement que PyInstaller ne détecte pas seul.

Compte 2 à 5 minutes. Résultat : `dist\NetGate.exe`, autonome, d'environ 30 Mo, qui demande lui-même l'élévation UAC. Les dossiers `build/`, `dist/` et le fichier `NetGate.spec` peuvent ensuite être supprimés.

> Un antivirus trop zélé peut bloquer PyInstaller : c'est la cause la plus fréquente d'échec.

---

## Fichiers et données

Tout est rangé **à côté de `netgate.py`** (ou de `NetGate.exe`). Si ce dossier n'est pas inscriptible (Program Files, clé USB protégée, dossier réseau), repli automatique sur `%APPDATA%\NetGate`.

| Fichier | Contenu |
|---|---|
| `netgate.state.json` | Réglages, profils, autorisations, compteurs du jour, historique, catalogue des programmes vus. **Copie-le pour sauvegarder ta configuration.** Renomme-le pour repartir de zéro. |
| `netgate.log` | Trace de démarrage et erreurs éventuelles. |
| `netgate.ico` | Icône générée pour l'exécutable et la fenêtre. |

Dans le pare-feu Windows, toutes les règles créées portent le préfixe `NETGATE_` et sont visibles dans *Pare-feu Windows Defender avec fonctions avancées de sécurité* → *Règles de trafic sortant*.

> `netgate.state.json` contient les chemins de tes programmes et donc ton nom d'utilisateur : **il n'est pas versionné** dans ce dépôt (voir `.gitignore`).

---

## Dépannage

| Symptôme | Cause probable / remède |
|---|---|
| Plus rien ne se connecte, même les programmes autorisés | La case **DNS/DHCP** n'est pas cochée dans les réglages. |
| NetGate ne démarre pas | Lance-le depuis un *Terminal (administrateur)* pour voir l'erreur, ou consulte `netgate.log`. |
| Le comptage indique « global estimé » | `pywintrace` n'est pas installé ou la session ETW n'a pas pu démarrer. |
| Internet est resté bloqué après un plantage | Relance NetGate (il nettoie au démarrage), ou clique **PANIQUE**. En dernier recours : `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound` en administrateur. |
| Configuration corrompue | Renomme `netgate.state.json` et relance. |

---

## Structure du code

Un seul fichier, [`netgate.py`](netgate.py), organisé en sections :

```
CONSTANTES           identité, version, couleurs, GUID ETW, chemins
UTILITAIRES          is_admin, relaunch_as_admin, run_netsh, fmt_bytes…
PARE-FEU WINDOWS     class Firewall        — génération et exécution des scripts netsh
COMPTEUR ETW         class EtwMeter        — thread d'écoute Kernel-Network + repli psutil
DETECTION            class ConnScanner     — thread de découverte des connexions
ETAT                 class State           — chargement/sauvegarde JSON, périodes, profils
INSPECTEUR           GLOSSARY, class Inspector — qui est ce programme ?
NOTIFICATION         class AuthToast       — carte Autoriser / Bloquer / Plus tard
ICONE                build_icon_image, write_ico — blason dynamique
ZONE DE NOTIFICATION class Tray            — pystray et son menu
AIDE INTEGREE        HELP                  — contenu de la fenêtre F1
FENETRE PRINCIPALE   class NetGateApp      — Tkinter, réglages, liste, plages horaires
DEMARRAGE            main()                — élévation UAC, mode limité, capture d'erreurs
```

Conventions : tout est en français, sans accents dans les identifiants et les commentaires ; les couleurs sont des constantes `C_*` ; chaque appel `netsh` coûte ~200 ms, d'où le regroupement systématique en scripts.

---

## Historique des versions

| Version | Changements |
|---|---|
| **1.3** | Plages horaires : tableau de 48 demi-heures dans les réglages, hors plage plus aucun programme ne sort. |
| 1.2 | L'enveloppe n'est décomptée que lorsque la protection est active ; hors protection le trafic est mesuré mais affiché à part. Trace de la remise à zéro au démarrage. Bascule forcée si l'horloge a reculé. |
| 1.1 | Numéro de version affiché dans le titre, la barre d'état et l'aide. Remise à zéro du compteur déplacée dans les réglages. |
| 1.0 | Version initiale : filtrage par application via le pare-feu Windows, comptage ETW par processus, enveloppe journalière avec alertes, notifications d'autorisation, icône dans la zone de notification, profils facultatifs, aide intégrée (F1). |

Numérotation : `V<majeure>.<mineure>`, plus une lettre pour une retouche cosmétique (`V1.1a`).

---

## Licence

[GNU GPL v3](LICENSE) — ETDEL © 2026.

NetGate est un logiciel libre : tu peux le redistribuer et le modifier selon les termes de la GNU General Public License version 3, telle que publiée par la Free Software Foundation. Il est distribué sans aucune garantie ; voir le fichier [LICENSE](LICENSE) pour le texte complet.
