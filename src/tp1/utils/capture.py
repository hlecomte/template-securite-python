from src.tp1.utils.lib import choose_interface
from src.tp1.utils.lib import choose_file
from tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.file = choose_file()
        self.summary = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic with the methode choice by user
        Returns:

        """
        while self.interface is None and self.file is None:
            logger.warning("No capture source specified")
            choix = input("1 : interface réseau | 2 : fichier .pcap : ").strip()

            if choix == "1":
                interface = input("Nom de l'interface : ").strip()
                if interface:
                    self.interface = interface
                else:
                    logger.error("Nom d'interface vide")
            elif choix == "2":
                path = input("Chemin du fichier .pcap : ").strip()
                if os.path.isfile(path):
                    self.file = path
                else:
                    logger.error("Fichier introuvable : %s", path)
            else:
                logger.error("Choix indisponible : %r", choix)

        if self.interface is not None:
            self.capture_traffic_from_interface()
        else:
            self.capture_traffic_from_file()

    def capture_traffic_from_interface(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")

    def capture_traffic_from_file(self) -> None:
        """
        Capture network traffic from a file
        """
        file = self.file
        logger.info(f"Capture traffic from file {file}")
        return

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        return ""

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        return ""

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate  summary
        """
        summary = ""
        return summary
