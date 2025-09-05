# WithSSL - Serveur Proxy SSL

WithSSL est un serveur proxy SSL puissant qui prend en charge la gestion automatique des certificats, le transfert de domaines, la protection de sécurité et le panneau d'administration web.

## 📚 Documentation

- 📑 [Index Complet de Documentation](DOCS.md) - Index et navigation pour tous les documents
- 📖 [Résumé du Projet (Chinois)](项目总结.md) - Introduction détaillée des fonctionnalités et documentation technique
- 🚀 [Guide de Déploiement (Anglais)](DEPLOYMENT_EN.md) - Documentation complète de déploiement et d'opérations
- 🚀 [部署指南 (中文)](DEPLOYMENT.md) - Guide de déploiement chinois
- 🇨🇳 [中文 README](README.md) - Version chinoise de ce document
- 🇺🇸 [English README](README_EN.md) - Version anglaise de ce document

## Fonctionnalités

### 🌏 Optimisation Réseau pour la Chine
- **Optimisation Proxy CDN**: Utilise le service [CDNProxy](https://cdnproxy.some.im/docs)
- **Accélération d'Accès**: Résout les problèmes d'accès jsdelivr CDN en Chine continentale
- **Stabilité**: Assure un chargement stable des ressources via le service proxy

### 🔒 Gestion Automatique des Certificats SSL
- Obtention automatique de certificats SSL depuis Let's Encrypt
- Support pour le renouvellement automatique des certificats
- Support pour les environnements de staging et de production
- Cache de certificats et optimisation des performances

### 🔄 Transfert Intelligent de Domaines
- Transfert proxy intelligent basé sur les noms de domaine
- Support pour les protocoles HTTP/HTTPS
- Support pour proxy WebSocket
- Pool de connexions et équilibrage de charge

### 🛡️ Protection de Sécurité
- Blocage IP et contrôle d'accès
- Protection contre les attaques par force brute
- Validation User-Agent
- Journalisation des accès

### 🎛️ Panneau d'Administration Web
- Interface web intuitive
- Surveillance et statistiques en temps réel
- Gestion des règles de proxy
- Gestion des certificats SSL
- Configuration de sécurité

### 🔄 Redémarrage Gracieux
- Redémarrage sans temps d'arrêt
- Préservation des connexions et récupération d'état
- Mécanisme d'arrêt gracieux

## Exigences Système

- Système Linux (Ubuntu/Debian/CentOS/RHEL)
- Go 1.21 ou supérieur
- Privilèges root
- Ports 80 et 443 disponibles

## Installation Rapide

### Installation Automatique

```bash
# Télécharger le script d'installation
curl -fsSL https://raw.githubusercontent.com/xurenlu/withssl/main/install.sh -o install.sh

# Exécuter le script d'installation
sudo bash install.sh
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

3. **Compiler WithSSL**
```bash
git clone https://github.com/xurenlu/withssl.git
cd withssl
go mod download
go build -o withssl main.go
```

## Configuration

### Configuration de Base

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false
  },
  "ssl": {
    "email": "your-email@example.com",
    "staging": false,
    "auto_renew": true
  },
  "admin": {
    "username": "admin",
    "password": "admin*9527",
    "first_run": true
  },
  "admin_prefix": "/withssl-panel"
}
```

## Utilisation

### Démarrer le Service
```bash
sudo systemctl start withssl
```

### Arrêter le Service
```bash
sudo systemctl stop withssl
```

### Panneau d'Administration Web

1. Ouvrir le navigateur et visiter: `https://your-domain/withssl-panel`
2. Se connecter avec les identifiants par défaut:
   - Nom d'utilisateur: `admin`
   - Mot de passe: `admin*9527`
3. Changer le mot de passe après la première connexion

## Arguments de Ligne de Commande

```bash
withssl --help
```

Options disponibles:
- `--config`: Chemin du fichier de configuration (par défaut: "/etc/withssl/withssl.conf")
- `--admin-prefix`: Préfixe du chemin du panneau d'administration (par défaut: "/withssl-panel")
- `--email`: Email pour certificat SSL
- `--port`: Port d'écoute (par défaut: 443)
- `--host`: Adresse d'écoute (par défaut: "0.0.0.0")
- `--version`: Afficher les informations de version

## Licence

Ce projet utilise la licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## Support

Si vous rencontrez des problèmes ou avez des suggestions:
1. Rechercher dans [Issues](https://github.com/xurenlu/withssl/issues)
2. Créer un nouveau Issue
3. Contacter les mainteneurs
