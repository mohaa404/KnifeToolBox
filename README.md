# 🗡️ Knife Tool Box

Knife Tool Box est une application Kivy développée dans le cadre d'un projet de Master 1 en Cyber Sécurité. Cette application permet de découvrir le réseau, de scanner les ports, de détecter les vulnérabilités et de générer des rapports détaillés sur les résultats.

## 🚀 Fonctionnalités

- Découverte de réseau : Permet de découvrir les hôtes actifs dans un réseau spécifié.
- Scan de ports : Permet de scanner les ports ouverts sur une adresse IP spécifique.
- Détection de vulnérabilités : Utilise nmap pour détecter les vulnérabilités sur une adresse IP.
- Génération de rapport : Génère un rapport PDF contenant les résultats des opérations précédentes.

## 🔧 Prérequis

- Python 3.x
- Kivy
- nmap
- matplotlib
- reportlab
- paramiko

## 🛠️ Installation

1. Clonez le dépôt :

    ```
    git clone https://github.com/mohaa404/KnifeToolBox.git
    ```

2. Installez les dépendances :

    ```
    cd KnifeToolBox
    pip install -r requirements.txt
    ```

3. Lancez l'application :

    ```
    python main.py
    ```

## 📋 Utilisation

1. Lancez l'application en exécutant `python main.py`.
2. Saisissez l'adresse IP que vous souhaitez analyser.
3. Utilisez les boutons pour effectuer les différentes opérations : découvrir le réseau, scanner les ports, détecter les vulnérabilités ou générer un rapport.
4. Les résultats seront affichés dans l'application et un rapport PDF sera généré.

## ✍️ Auteur

Développé par [Mohamed JEDDI M1 CYB B](https://github.com/mohaa404).

