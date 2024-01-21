import requests
import datetime
import socket
import time
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings

"""
==========================================================================
AUTHOR : DOUT7505
DATA   : 2024 01 21

USAGE  : Calculate HSTS / CSP score from Janus Internet

==========================================================================
"""
disable_warnings(InsecureRequestWarning)  # Désactiver les avertissements pour les requêtes non vérifiées
debug = 0

def get_host_from_url(url):
    if '://' in url:
        return url.split("://")[1].split("/")[0].split(":")[0]
    else:
        return url.split("/")[0].split(":")[0]

def check_secure_flag_in_cookies(cookies):
    for cookie in cookies.split(';'):
        if cookie.strip().lower().startswith('set-cookie'):
            if 'secure' not in cookie.lower():
                return False
    return True

# Definit l'heure de demarrage
start_time = time.time()

# Obtenir la date actuelle
curdate = datetime.datetime.now()

# Formater la date au format "AAAAMMJJ"
filedate = curdate.strftime("%Y%m%d")

# Utiliser la date formatée pour nommer votre fichier de log
logfile = f"{filedate}_hstschecker.log"

if debug == 1:
    print(f"LOGFILE : {logfile}")

# Ouvrir un fichier en mode écriture (créera le fichier s'il n'existe pas)
logf = open(logfile, 'w')


"""
# #########################################
# Headers qui devraient être presentes :
# #########################################
Strict-Transport-Security (HSTS): 
    Assure que les navigateurs interagissent avec votre site uniquement via des connexions HTTPS sécurisées.

Content-Security-Policy (CSP): 
    Aide à prévenir les attaques de type cross-site scripting (XSS) et d'autres attaques de type injection en spécifiant des sources de confiance pour le contenu.

X-Content-Type-Options: 
    Empêche le navigateur de faire des suppositions sur le type MIME des ressources (notamment, il bloque le mode "sniffing" du navigateur).

X-Frame-Options: 
    Protège contre les attaques par "clickjacking" en empêchant l'intégration de votre site dans des iframes de sites tiers.

Referrer-Policy: 
    Contrôle les informations envoyées comme référent lors de la navigation vers une autre page.

Permissions-Policy (anciennement Feature-Policy): 
    Permet de contrôler quelles fonctionnalités du navigateur doivent être autorisées ou bloquées sur votre site.

X-XSS-Protection: 
    Offre des protections supplémentaires contre les attaques XSS dans certains navigateurs (bien que devenu obsolète en faveur de CSP, il est encore parfois utilisé pour la compatibilité avec les anciens navigateurs).

Cross-Origin-Embedder-Policy (COEP): 
    Empêche le site de charger des ressources qui ne sont pas explicitement accordées via les en-têtes CORS.

Cross-Origin-Opener-Policy (COOP): 
    Isolation des sites pour prévenir les attaques par side-channel, comme Spectre.

Cross-Origin-Resource-Policy (CORP): 
    Permet aux serveurs de contrôler comment leurs ressources sont partagées avec d'autres documents au niveau de l'origine.
"""

# Points attribués pour chaque en-tête en fonction de son importance
header_points = {
    'Strict-Transport-Security': 2,
    'Content-Security-Policy': 3,
    'X-Content-Type-Options': 1,
    'X-Frame-Options': 2,
    'Referrer-Policy': 1,
    'Permissions-Policy': 2,
    'X-XSS-Protection': 1,
    'Cross-Origin-Embedder-Policy': 2,
    'Cross-Origin-Opener-Policy': 2,
    'Cross-Origin-Resource-Policy': 2
}

# Création d'une session pour maintenir les cookies et autres en-têtes de navigateur
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5'
})

timeout_seconds = 2

with open('urls.txt') as f:
    for content in f:
        content = content.strip()

        # Ignorer les lignes vides
        if not content:
            continue

        # Obtenir la date et l'heure actuelles
        now = f"[{datetime.datetime.now()}]"

        try:
            host = get_host_from_url(content)
            ip = socket.gethostbyname(host)
            headers = {'Host': host}
            url = f"https://{ip}"


            response = session.get(url, headers=headers, verify=False, allow_redirects=True, timeout=timeout_seconds)
            security_score = 0

            print("===========================================================")

            if debug == 1:
                print(f"{now}\tURL: {content} (Resolved IP: {ip})")

            print(f"{now}\t{content} (Resolved IP: {ip})\tStatus Code: {response.status_code}")
            logf.write(f"{now}\t{content} (Resolved IP: {ip})\tStatus Code: {response.status_code}\n")

            # Obtenir l'URL finale après les redirections
            final_url = response.url

            print(f"{now}\t{content} (Resolved IP: {ip})\tFinal URL: {final_url}")
            logf.write(f"{now}\t{content} (Resolved IP: {ip})\tFinal URL: {final_url}\n")

            for key, value in response.headers.items():
                if debug == 1:
                    print(f"{now}\t{content} (Resolved IP: {ip})\t{key}: {value}")
                logf.write(f"{now}\t{content} (Resolved IP: {ip})\t{key}: {value}\n")

                if key.lower() == 'set-cookie':
                    secure_flag = check_secure_flag_in_cookies(value)
                    if secure_flag:
                        print(f"\033[92m{now}\t{content} (Resolved IP: {ip})\tCookie '{value.split(';')[0]}' has Secure flag\033[0m")
                        logf.write(f"{now}\t{content} (Resolved IP: {ip})\tCookie '{value.split(';')[0]}' has Secure flag\n")
                    else:
                        print(f"\033[91m{now}\t{content} (Resolved IP: {ip})\tCookie '{value.split(';')[0]}' is missing Secure flag\033[0m")
                        logf.write(f"{now}\t{content} (Resolved IP: {ip})\tCookie '{value.split(';')[0]}' is missing Secure flag\n")

            # Count points with Dict
            for header in header_points:
                if header in response.headers:
                    print(f"\033[92m{now}\t{content} (Resolved IP: {ip})\t{header}: {response.headers[header]} FOUND\033[0m")
                    logf.write(f"{now}\t{content} (Resolved IP: {ip})\t{header}: {response.headers[header]} FOUND\n")
                    security_score += header_points[header]
                else:
                    print(f"\033[91m{now}\t{content} (Resolved IP: {ip})\t{header}: MISSING\033[0m")
                    logf.write(f"{now}\t{content} (Resolved IP: {ip})\t{header}: MISSING\n")

            print(f"\033[93m{now}\t{content} (Resolved IP: {ip})\tHSTS/CSP Score: {security_score}/{sum(header_points.values())}\033[0m")
            logf.write(f"{now}\t{content} (Resolved IP: {ip})\tHSTS/CSP Score: {security_score}/{sum(header_points.values())}\n")

        except Exception as e:
            print("===========================================================")
            print(f"{now}\tURL: {content} (Resolved IP: {ip} : Error: {e})")
            logf.write(f"{now}\tURL: {content} (Resolved IP: {ip} : Error: {e})\n")
            print(f"\033[93m{now}\t{content} (Resolved IP: {ip})\tHSTS/CSP Score: KO\033[0m")
            logf.write(f"{now}\t{content} (Resolved IP: {ip})\tHSTS/CSP Score: KO\n")

end_time = time.time()
print("")
print("It took --- {} seconds --- for all the links".format(end_time - start_time))
logf.write(f"{now}\tTOTAL Time : {(end_time - start_time)}\n")


