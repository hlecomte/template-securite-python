import requests
from src.tp3.utils.captcha import Captcha


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
        print(f"CAPTCHA reconnu: {self.captcha_value} ")

    def submit_request(self):
        """Envoie la captcha au serveur."""
        if not self.captcha_value:
            raise ValueError("Aucun CAPTCHA reconnu")

        self.response = self.session.post(
            self.url,
            data={"captcha": self.captcha_value},
            timeout=5
        )

        print(f"Statut HTTP : {self.response.status_code}")
        print(f"Réponse du serveur : {self.response.text}")

    def process_response(self):
        """Analyse la réponse du serveur."""
        if self.response is None:
            raise ValueError("Aucune réponse du serveur")

        if self.response.status_code != 200:
            print("Erreur : CAPTCHA incorrect")
            return

        data = self.response.json()

        self.valid_flag = data.get("flag1", "")
        self.host = data.get("host", "")
        self.port = data.get("port", 0)
        self.key = data.get("key", "")

        print(f"Flag 1 : {self.valid_flag}")
        print(f"Adresse du serveur : {self.host}")
        print(f"Port TCP : {self.port}")
        print(f"Clé : {self.key}")

    def get_flag(self):
        """Retourne le drapeau récupéré."""
        return self.valid_flag
