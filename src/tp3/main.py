import argparse
import requests

from pathlib import Path
from tp3.utils.config import logger


def sentinel_dda268():
    """Initialise le programme."""
    return True
    
def fuzz_endpoints(target: str) -> str | None:
    """Ajout de la fonction de fuzzing pour tester les chemins de la wordlist dans le but de trouver la page cachée."""

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
                    return url

                logger.info(f"Ressource trouvée ({content_type}) : {url}")

        except requests.RequestException as erreur:
            logger.warning(f"Erreur HTTP sur {url} : {erreur}")

    return None

def breach_web(target: str) -> tuple[str, int, bytes]:
   """Fonction qui va trouver la page cachée puis préparer la phase CAPTCHA."""

    hidden_url = fuzz_endpoints(target)

    if hidden_url is None:
        logger.error("Aucune page HTML cachée trouvée.")
        raise RuntimeError("Fuzzing : aucun endpoint trouvé")

    logger.info(f"Page candidate trouvée : {hidden_url}")
    raise NotImplementedError("CAPTCHA")


def breach_network(host: str, port: int, key: bytes) -> str:
    """Fonction qui permet de décoder les messages TCP pour récupérer le drapeau final."""
    
    raise NotImplementedError("Réseau")


def main() -> None:
    sentinel_dda268()
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key)
    logger.info(f"FLAG_FINAL: {flag}")


if __name__ == "__main__":
    main()
