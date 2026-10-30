import argparse
import requests
import base64
import re
import socket

from pathlib import Path
from urllib.parse import urlparse
from tp3.utils.config import logger
from tp3.utils.session import Session


def fuzz_endpoints(target: str) -> str | None:
    """Ajout de la fonction de fuzzing pour tester
    les chemins de la wordlist dans le but de trouver la page cachée."""

    wordlist = Path(__file__).parent / "wordlist.txt"
    endpoints = wordlist.read_text(encoding="utf-8").splitlines()
    for endpoint in endpoints:
        endpoint = endpoint.strip()

        if not endpoint or endpoint.startswith("#"):
            continue
        url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"

        try:
            response = requests.get(url, timeout=3)
            logger.info(f"{url} : HTTP {response.status_code}")

            if response.status_code not in (200, 404):
                logger.info(
                    f"Autre réponse intéressante : {url} "
                    f"(HTTP {response.status_code})"
                )
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")

                if "text/html" in content_type.lower():
                    logger.info(f"Page HTML candidate: {url}")

                    if "captcha" in response.text.lower():
                        logger.info(f"Challenge CAPTCHA trouvé: {url}")
                        return url

                logger.info(f"Ressource trouvée ({content_type}) : {url}")

        except requests.RequestException as erreur:
            logger.warning(f"Erreur HTTP sur {url} : {erreur}")

    return None


def breach_web(target: str) -> tuple[str, int, bytes]:
    """Fonction qui va trouver la page cachée puis récupérer les paramètres TCP."""

    hidden_url = fuzz_endpoints(target)

    if hidden_url is None:
        raise RuntimeError("Aucune page CAPTCHA trouvée.")

    logger.info(f"Page trouvée : {hidden_url}")

    session = Session(hidden_url)
    session.prepare_request()

    session.submit_request()
    session.process_response()

    flag1 = session.get_flag()

    if not flag1:
        raise RuntimeError("FLAG1 non récupéré")

    print(f"[+] FLAG1: {flag1}")

    host = session.host
    port = int(session.port)
    key = bytes.fromhex(session.key)

    if host in ("127.0.0.1", "localhost", "0.0.0.0"):
        host = urlparse(target).hostname

    return host, port, key


def breach_network(host: str, port: int, key: bytes) -> str:
    """Fonction qui permet de décoder les tokens TCP pour récupérer le drapeau final."""
    if not key:
        raise ValueError("Clé XOR vide")

    with socket.create_connection((host, port), timeout=5) as connexion:
        connexion.settimeout(4)

        with connexion.makefile("rwb") as flux:
            while True:
                ligne = flux.readline()

                if not ligne:
                    raise RuntimeError("Connexion TCP fermée sans flag")

                message = ligne.decode("utf-8").strip()
                logger.info(f"Serveur TCP : {message}")

                resultat = re.search(r"ESGI\{[^}]+\}", message)

                if resultat:
                    return resultat.group(0)

                if message.startswith("Decode each line:"):
                    continue

                if message == "TIMEOUT":
                    raise RuntimeError("Délai TCP dépassé")

                data = base64.b64decode(message, validate=True)

                decoded = bytes(
                    byte ^ key[i % len(key)]
                    for i, byte in enumerate(data)
                )

                token = decoded.decode("utf-8")

                flux.write((token + "\n").encode("utf-8"))
                flux.flush()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key)
    logger.info(f"FLAG_FINAL: {flag}")


if __name__ == "__main__":
    main()
