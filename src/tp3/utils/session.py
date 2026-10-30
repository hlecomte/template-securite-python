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
        """Envoie la réponse au serveur."""
        raise NotImplementedError("Endpoint de soumission inconnu")

    def process_response(self):
        """Analyse la réponse du serveur."""
        raise NotImplementedError("Réponse du serveur à déterminé")

    def get_flag(self):
        """Retourne le drapeau récupéré."""
        return self.valid_flag
