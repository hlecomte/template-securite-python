from io import BytesIO

import requests
import pytesseract
from PIL import Image, ImageOps

class Captcha:
    def __init__(self, url):
        self.url = url
        self.image = None
        self.value = ""
        self.session = session or requests.Session()


    def solve(self):
        """Fonction permettant l'analyse du captcha."""
        if self.image is None:
            self.capture()

        image = ImageOps.grayscale(self.image)

        image = image.resize(
            (image.width * 3, image.height * 3)
        )
        
        image = ImageOps.autocontrast(image)

        image = image.point(
            lambda pixel: 255 if pixel > 150 else 0
        )
        
        image.save("/tmp/captcha_pretraite.png")

        texte = pytesseract.image_to_string(
            image,
            config="--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        )

        self.value = texte.strip().upper()

    def capture(self):
        """Fonction permettant de récupérer la capture du captcha depuis le serveur."""
        response = requests.get(self.url, timeout=5)
        response.raise_for_status()

        self.image = Image.open(BytesIO(response.content)).convert("RGB")

    def get_value(self):
        """Fonction retournant la valeur du captcha"""
        return self.value
