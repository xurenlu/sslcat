# SSLcat - Serveur Proxy SSL

## ⏱️ Démarrage Rapide avec SSLcat en 1 Minute

```bash
# 1) Installation en un clic (Linux)
# Pour les utilisateurs en Chine continentale (accéléré via sslcat.com)
curl -fsSL https://sslcat.com/xurenlu/sslcat/main/scripts/install-from-release-zh.sh | sudo bash -s -- -v 1.0.11
# Les utilisateurs hors Chine continentale peuvent utiliser directement GitHub raw :
# curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release.sh | sudo bash -s -- -v 1.0.11

# 2) Test rapide local macOS (ou télécharger le paquet darwin manuellement)
curl -fsSL https://sslcat.com/xurenlu/sslcat/releases/download/v1.0.11/sslcat_1.0.11_darwin_arm64.tar.gz -o sslcat.tgz
tar -xzf sslcat.tgz && sudo install -m 0755 sslcat /usr/local/bin/sslcat
sslcat --config sslcat.conf --port 8080
# Accès navigateur : http://localhost:8080/sslcat-panel/
# Première connexion : admin / admin*9527 (forcera le changement de mot de passe et générera admin.pass)

# 3) Optionnel : Démarrage en un clic avec Docker Compose
docker compose up -d
```

SSLcat est un serveur proxy SSL puissant qui prend en charge la gestion automatique des certificats, le transfert de domaines, la protection de sécurité et le panneau d'administration web, avec support des protocoles HTTP/3 (QUIC) et HTTP/2 (négociation automatique, compatible vers le bas).

## 📚 Navigation de la Documentation

- 📑 [Index Complet de Documentation](DOCS.md) - Index et navigation pour tous les documents
- 📖 [Résumé du Projet](项目总结.md) - Introduction détaillée des fonctionnalités et documentation technique
- 🚀 [Guide de Déploiement (Chinois)](DEPLOYMENT.md) - Documentation complète de déploiement et d'opérations
- 🚀 [Guide de Déploiement (Anglais)](DEPLOYMENT_EN.md) - Guide de déploiement anglais

### 🌍 Versions Multilingues
- 🇨🇳 [中文 README](README.md) - Version chinoise
- 🇺🇸 [English README](README_EN.md) - Version anglaise
- 🇯🇵 [日本語 README](README_JA.md) - Version japonaise  
- 🇪🇸 [Español README](README_ES.md) - Version espagnole
- 🇷🇺 [Русский README](README_RU.md) - Version russe

## Caractéristiques

### 🌏 Optimisation Réseau pour la Chine
- **Optimisation Proxy CDN** : Utilise le service proxy [CDNProxy](https://cdnproxy.some.im/docs)
- **Accélération d'Accès** : Résout les problèmes d'accès jsdelivr CDN en Chine continentale
- **Stabilité** : Assure un chargement stable des ressources via le service proxy

### 🔒 Gestion Automatique des Certificats SSL
- Obtention automatique de certificats SSL depuis Let's Encrypt
- Support pour le renouvellement automatique des certificats
- Support pour les environnements de staging et de production
- Cache de certificats et optimisation des performances
- **Opérations de Certificats en Lot** : Téléchargement/importation de tous les certificats en un clic (format ZIP)

### 🔄 Transfert Intelligent de Domaines
- Transfert proxy intelligent basé sur les noms de domaine
- Support pour les protocoles HTTP/HTTPS
- Support pour proxy WebSocket
- Pool de connexions et équilibrage de charge

### 🛡️ Mécanismes de Protection de Sécurité
- Blocage IP et contrôle d'accès
- Protection anti-force brute
- Validation User-Agent
- Journalisation des accès
- **Empreinte Client TLS** : Identification de client basée sur les caractéristiques ClientHello
- **Optimisation Environnement de Production** : Seuils de sécurité plus tolérants pour les scénarios de trafic élevé

### 🎛️ Panneau d'Administration Web
- Interface web intuitive
- Surveillance et statistiques en temps réel
- Gestion des règles de proxy
- Gestion des certificats SSL
- Configuration de sécurité
- **Gestion des Tokens API** : Contrôle d'accès API lecture seule/lecture-écriture
- **Statistiques d'Empreintes TLS** : Données d'analyse d'empreintes client en temps réel

### 🔄 Redémarrage Gracieux
- Redémarrage sans temps d'arrêt
- Préservation des connexions et récupération d'état
- Mécanisme d'arrêt gracieux

## Exigences Système

- Système Linux (Ubuntu/Debian/CentOS/RHEL)
- Go 1.21 ou supérieur
- Privilèges root
- Ports 80 et 443 disponibles

## 📥 Obtenir le Code Source

### Dépôt GitHub

Projet hébergé sur GitHub : **[https://github.com/xurenlu/sslcat](https://github.com/xurenlu/sslcat)**

### Téléchargement de la Dernière Version

```bash
# Cloner le code source le plus récent
git clone https://github.com/xurenlu/sslcat.git
cd sslcat

# Ou télécharger une version spécifique (recommandé)
wget https://github.com/xurenlu/sslcat/archive/refs/heads/main.zip
unzip main.zip
cd sslcat-main
```

## 🚀 Installation Rapide

### Installation Automatique (Recommandé)

```bash
# Télécharger le script d'installation depuis GitHub
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh -o install.sh

# Exécuter le script d'installation
sudo bash install.sh
```

### Déploiement Intégré (Fichier Unique)

```bash
# Générer le paquet de déploiement intégré
./deploy-embedded.sh

# Ou générer la version Linux
./deploy-embedded.sh linux

# Puis télécharger le répertoire deploy/ sur le serveur
```

### Installation Manuelle

1. **Installer les Dépendances**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y curl wget git build-essential ca-certificates certbot

# CentOS/RHEL
sudo yum update -y
sudo yum install -y curl wget git gcc gcc-c++ make ca-certificates certbot
```

2. **Installer Go**
```bash
# Télécharger et installer Go 1.21
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

3. **Compiler SSLcat**
```bash
git clone https://github.com/xurenlu/sslcat.git
cd sslcat
go mod download
go build -o sslcat main.go
```

4. **Créer Utilisateur et Répertoires**
```bash
sudo useradd -r -s /bin/false sslcat
sudo mkdir -p /etc/sslcat /var/lib/sslcat/{certs,keys,logs}
sudo chown -R sslcat:sslcat /var/lib/sslcat
```

5. **Configurer et Démarrer**
```bash
sudo cp sslcat /opt/sslcat/
sudo cp sslcat.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sslcat
sudo systemctl start sslcat
```

## Configuration

### Emplacement du Fichier de Configuration
- Fichier de configuration principal : `/etc/sslcat/sslcat.conf`
- Répertoire des certificats : `/var/lib/sslcat/certs`
- Répertoire des clés : `/var/lib/sslcat/keys`
- Répertoire des logs : `/var/lib/sslcat/logs`

### Configuration de Base

```yaml
server:
  host: "0.0.0.0"
  port: 443
  debug: false

ssl:
  email: "your-email@example.com"  # Email pour certificat SSL
  staging: false                   # Si utiliser l'environnement de staging
  auto_renew: true                 # Renouvellement automatique

admin:
  username: "admin"
  password_file: "/var/lib/sslcat/admin.pass"     # Mot de passe sauvegardé dans ce fichier, sslcat.conf ne persiste pas password
  first_run: true

proxy:
  rules:
    - domain: "example.com"
      target: "127.0.0.1"
      port: 8080
      enabled: true
      ssl_only: true

security:
  max_attempts: 3                  # Max. tentatives échouées en 1 minute
  block_duration: "1m"             # Durée du blocage
  max_attempts_5min: 10            # Max. tentatives échouées en 5 minutes

admin_prefix: "/sslcat-panel"     # Préfixe du chemin du panneau d'administration
```

### Récupération de Mot de Passe (Récupération d'Urgence)

SSLcat utilise la stratégie de sécurité "fichier marqueur + changement forcé de mot de passe au premier usage" :

- Fichier marqueur : `admin.password_file` (par défaut `./data/admin.pass`). Le fichier sauvegarde le mot de passe admin actuel avec permissions 0600.
- Première connexion : Si le fichier marqueur n'existe pas, ou si le contenu du fichier est toujours le mot de passe par défaut `admin*9527`, l'admin sera forcé à la page "changer mot de passe" après connexion réussie pour établir un nouveau mot de passe et écrire dans le fichier marqueur.

Étapes de récupération de mot de passe :

1. Arrêter le service (ou le maintenir en fonctionnement, arrêt recommandé).
2. Supprimer le fichier marqueur (si le chemin a changé, supprimer selon le chemin réel de configuration) :
   ```bash
   rm -f ./data/admin.pass
   ```
3. Redémarrer le service, se connecter avec le compte par défaut (admin / admin*9527).
4. Le système forcera l'entrée dans la page "changer mot de passe", établir un nouveau mot de passe pour restaurer l'opération normale.

Note : Pour des raisons de sécurité, `sslcat.conf` ne persiste plus `admin.password` en texte clair lors de la sauvegarde ; au moment de l'exécution, le mot de passe réel utilise `admin.password_file` comme standard.

## Utilisation

### Démarrer le Service
```bash
sudo systemctl start sslcat
```

### Arrêter le Service
```bash
sudo systemctl stop sslcat
```

### Redémarrer le Service
```bash
sudo systemctl restart sslcat
```

### Redémarrage Gracieux
```bash
sudo systemctl reload sslcat
# ou envoyer signal SIGHUP
sudo kill -HUP $(pgrep sslcat)
```

### Voir les Logs
```bash
# Voir l'état du service
sudo systemctl status sslcat

# Voir les logs en temps réel
sudo journalctl -u sslcat -f

# Voir les logs d'erreur
sudo journalctl -u sslcat -p err
```

## Panneau d'Administration Web

### Accéder au Panneau d'Administration
1. Ouvrir le navigateur et visiter : `https://your-domain/sslcat-panel`
2. Se connecter avec les identifiants par défaut :
   - Nom d'utilisateur : `admin`
   - Mot de passe : `admin*9527`
3. Changer le mot de passe après la première connexion

### Fonctions du Panneau d'Administration
- **Tableau de Bord** : Voir l'état du système et les statistiques
- **Configuration Proxy** : Gérer les règles de transfert de domaines
- **Certificats SSL** : Voir et gérer les certificats SSL
- **Paramètres de Sécurité** : Configurer les politiques de sécurité et voir les IPs bloquées
- **Paramètres Système** : Modifier la configuration système

## Configuration Proxy

### Ajouter une Règle Proxy
1. Se connecter au panneau d'administration
2. Aller à la page "Configuration Proxy"
3. Cliquer sur "Nouvelle Règle Proxy"
4. Remplir la configuration :
   - Domaine : Domaine à proxifier
   - Cible : IP ou domaine du serveur backend
   - Port : Port du service backend
   - Activé : Si activer cette règle
   - SSL Seulement : Si permettre seulement l'accès HTTPS

### Exemple de Règle Proxy
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "127.0.0.1"
      port: 3000
      enabled: true
      ssl_only: true
    - domain: "app.example.com"
      target: "192.168.1.100"
      port: 8080
      enabled: true
      ssl_only: false
```

## Gestion des Certificats SSL

### Acquisition Automatique de Certificats
SSLcat obtient automatiquement les certificats SSL pour les domaines configurés sans intervention manuelle.

### Renouvellement de Certificats
Les certificats sont automatiquement renouvelés 30 jours avant l'expiration, ou peuvent être déclenchés manuellement.

### Stockage de Certificats
- Fichier de certificat : `/var/lib/sslcat/certs/domain.crt`
- Fichier de clé privée : `/var/lib/sslcat/keys/domain.key`

## Fonctions de Sécurité

### Mécanisme de Blocage IP
- Blocage automatique après 3 tentatives échouées en 1 minute
- Blocage automatique après 10 tentatives échouées en 5 minutes
- Durée de blocage configurable
- Support pour déblocage manuel

### Contrôle d'Accès
- Validation User-Agent
- Rejeter l'accès avec User-Agent vide
- Rejeter l'accès avec User-Agent de navigateurs peu communs

### Débloquer les IPs
```bash
# Supprimer le fichier de blocage et redémarrer le service
sudo rm /var/lib/sslcat/sslcat.block
sudo systemctl restart sslcat
```

## Arguments de Ligne de Commande

```bash
sslcat [options]

Options :
  --config string        Chemin du fichier de configuration (par défaut : "/etc/sslcat/sslcat.conf")
  --admin-prefix string  Préfixe du chemin du panneau d'administration (par défaut : "/sslcat-panel")
  --email string         Email pour certificat SSL
  --staging             Utiliser l'environnement de staging Let's Encrypt
  --port int            Port d'écoute (par défaut : 443)
  --host string         Adresse d'écoute (par défaut : "0.0.0.0")
  --log-level string    Niveau de log (par défaut : "info")
  --version             Afficher les informations de version
```

## Dépannage

### Problèmes Courants

1. **Échec de démarrage du service**
   ```bash
   # Vérifier la syntaxe du fichier de configuration
   sudo withssl --config /etc/sslcat/withssl.conf --log-level debug
   
   # Vérifier l'utilisation du port
   sudo netstat -tlnp | grep :443
   ```

2. **Échec d'acquisition de certificat SSL**
   - S'assurer que la résolution du domaine soit correcte
   - S'assurer que le port 80 soit accessible
   - Vérifier les paramètres du pare-feu
   - Utiliser l'environnement de staging pour les tests

3. **Échec de transfert proxy**
   - Vérifier si le serveur cible est atteignable
   - Vérifier que le port soit correct
   - Consulter les logs d'accès

4. **Panneau d'administration inaccessible**
   - Vérifier les paramètres du pare-feu
   - Vérifier que le certificat SSL soit valide
   - Consulter les logs du service

### Analyse des Logs
```bash
# Voir les logs détaillés
sudo journalctl -u sslcat -f --no-pager

# Filtrer les logs d'erreur
sudo journalctl -u sslcat -p err --since "1 hour ago"

# Voir les logs d'une période spécifique
sudo journalctl -u sslcat --since "2024-01-01 00:00:00" --until "2024-01-01 23:59:59"
```

## Optimisation des Performances

### Optimisation Système
```bash
# Augmenter la limite des descripteurs de fichier
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimiser les paramètres réseau
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### Optimisation de Configuration
```yaml
server:
  # Activer le mode debug pour l'analyse des performances
  debug: false
  
proxy:
  # Configurer un nombre raisonnable de règles proxy
  rules: []
  
security:
  # Ajuster les paramètres de sécurité
  max_attempts: 5
  block_duration: "5m"
```

## Optimisation Réseau

### Optimisation pour les Utilisateurs de Chine Continentale

SSLcat a été optimisé pour l'environnement réseau de la Chine continentale, utilisant le service proxy [CDNProxy](https://cdnproxy.some.im/docs) pour résoudre les problèmes d'accès jsdelivr CDN.

#### Utilisation du Proxy CDN
- **Adresse originale** : `https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css`
- **Adresse proxy** : `https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css`

#### Fichiers de Ressources Impliqués
- Bootstrap 5.1.3 CSS
- Bootstrap Icons 1.7.2
- Bootstrap 5.1.3 JavaScript
- Bibliothèque Axios JavaScript

#### Contrôle d'Accès
Selon la documentation CDNProxy, le service implémente des politiques de contrôle d'accès. Si l'accès est bloqué, c'est habituellement parce que le domaine Referer de la requête n'est pas dans la liste blanche. Contacter l'administrateur du service pour ajouter votre domaine à la liste blanche si nécessaire.

## Guide de Développement

### Structure du Projet
```
sslcat/
├── main.go                 # Entrée principale du programme
├── go.mod                  # Fichier de module Go
├── internal/               # Paquets internes
│   ├── config/            # Gestion de configuration
│   ├── logger/            # Gestion des logs
│   ├── ssl/               # Gestion des certificats SSL
│   ├── proxy/             # Gestion proxy
│   ├── security/          # Gestion de sécurité
│   ├── web/               # Serveur web
│   └── graceful/          # Redémarrage gracieux
├── web/                   # Ressources web
│   ├── templates/         # Modèles HTML
│   └── static/            # Ressources statiques
├── install.sh             # Script d'installation
└── README.md              # Documentation
```

### Configuration de l'Environnement de Développement
```bash
# Cloner le projet
git clone https://github.com/xurenlu/sslcat.git
cd sslcat

# Installer les dépendances
go mod download

# Exécuter le serveur de développement
go run main.go --config sslcat.conf --log-level debug
```

### Guide de Contribution
1. Fork du projet
2. Créer une branche de fonctionnalité
3. Confirmer les changements
4. Push vers la branche
5. Créer une Pull Request

## Licence

Ce projet utilise la licence MIT. Voir le fichier [LICENSE](LICENSE) pour les détails.

## Support

Si vous rencontrez des problèmes ou avez des suggestions :
1. Consulter la section [Dépannage](#dépannage)
2. Rechercher dans [Issues](https://github.com/xurenlu/sslcat/issues)
3. Créer un nouveau Issue
4. Contacter les mainteneurs

## Changelog

### v1.0.0 (2024-01-01)
- Version initiale
- Support pour la gestion automatique des certificats SSL
- Support pour le transfert proxy de domaines
- Support pour le panneau d'administration web
- Support pour les mécanismes de protection de sécurité
- Support pour la fonctionnalité de redémarrage gracieux