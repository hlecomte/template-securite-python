import requests
from src.tp3.utils.captcha import Captcha
from tp3.utils.config import logger

class Session:
    """Prépare les infos nécessaires au challenge web."""

    def __init__(self, url):
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.session = requests.Session()
        self.response = None

    def prepare_request(self):
        """Télécharge et résout le captcha."""
        response = self.session.get(self.url, timeout=5)
        response.raise_for_status()

        captcha_url = requests.compat.urljoin(
            self.url, "/captcha.png"
        )
        captcha = Captcha(captcha_url, self.session)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        logger.info(f"CAPTCHA reconnu: {self.captcha_value} ")

    def submit_request(self):
        """Envoie la captcha au serveur."""
        if not self.captcha_value:
            raise ValueError("Aucun CAPTCHAf reconnu")

        self.response = self.session.post(
            self.url,
            data={"captcha": self.captcha_value},
            timeout=5
        )

        logger.info(f"Statut HTTP : {self.response.status_code}")
        logger.info(f"Réponse du serveur : {self.response.text}")

    def process_response(self):
        """Analyse la réponse du serveur."""
        if self.response is None:
            raise ValueError("Aucune réponse du serveur")

        if self.response.status_code != 200:
            logger.error("Erreur : CAPTCHA incorrect")
            return

        data = self.response.json()

        self.valid_flag = data.get("flag1", "")
        self.host = data.get("host", "")
        self.port = data.get("port", 0)
        self.key = data.get("key", "")

        logger.info(f"Flag 1 : {self.valid_flag}")
        logger.info(f"Adresse du serveur : {self.host}")
        logger.info(f"Port TCP : {self.port}")
        logger.info(f"Clé : {self.key}")

    def get_flag(self):
        """Retourne le drapeau récupéré."""
        return self.valid_flag
