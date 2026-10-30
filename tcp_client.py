import socket
import base64
from tp3.utils.config import logger

host = "127.0.0.1"
port = 9090
key = bytes.fromhex("ff193b22")

with socket.create_connection((host, port), timeout=5) as connexion:
    with connexion.makefile("rwb") as flux:
        while True:
            ligne = flux.readline()

            if not ligne:
                break

            message = ligne.decode("utf-8").strip()
            logger.info("Serveur :", message)
            if message.startswith("OK ESGI{"):
                logger.info("Challenge TCP réussi !")
                logger.info("Flag 2 :", message.split("OK ", 1)[1])
                break

            if message.startswith("Decode each line:"):
                continue

            try:
                data = base64.b64decode(message, validate=True)

                decoded = bytes(
                    byte ^ key[i % len(key)]
                    for i, byte in enumerate(data)
                )

                token = decoded.decode("utf-8")

                logger.info("Token décodé : {token}")

                flux.write((token + "\n").encode("utf-8"))
                flux.flush()

            except (ValueError, UnicodeDecodeError):
                logger.warning(f"Message non décodable : {message}")
                break