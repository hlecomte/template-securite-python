from src.tp1.utils.lib import choose_interface, choose_file
from tp1.utils.config import logger
from scapy.all import sniff, rdpcap, wrpcap, PcapReader
from collections import Counter, defaultdict


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.file = choose_file()
        self.packets = ""
        self.alerts = None
        self.all_protocols = None
        self.summary = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic with the methode choice by user
        Returns:

        """
        while self.interface is "" and self.file is "":
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

        if self.interface is not "":
            self.capture_traffic_from_interface()
        else:
            self.capture_traffic_from_file()


    def capture_traffic_from_interface(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")

        self.packets = sniff(ifaces=interface, count=100)



    def capture_traffic_from_file(self) -> None:
        """
        Capture network traffic from a file
        """
        file = self.file
        logger.info(f"Capture traffic from file {file}")

        self.packets = rdpcap(file)


    def sort_network_protocols(self) -> dict:
        """
        Sort and return all captured network protocols
        """
        logger.info(f"Sorting network protocols")
        protocol_trie = dict(sorted((self.all_protocols.items(), key=lambda item: item[1])))
        return protocol_trie

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """

        counter = Counter()

        logger.info(f"Comptabilisation of protocols")
        for pkt in self.packets:
            for name in {layer.__name__ for layer in pkt.layers()}:
                counter[name] += 1

        return counter

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
        self.all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {self.all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.alerts += self.attack_warning(protocols)
        self.summary = self._gen_summary()

    def attack_warning(self, protocoles: str) -> list[Alert]:
        """

        Returns:

        """
        alerts = []
        for pkt in self.packets:
            for match in self.rules.match(data=payload):
                alerts.append(Alert(
                    attack=match.rule,
                    protocol="TCP" if pkt.haslayer(protocoles) else "Autre",
                    ip=self._get_ip(pkt),
                    mac=self._get_mac(pkt),
                    details=match.meta.get("description", ""),
                ))

        return alerts

    def _gen_summary(self) -> str:
        """
        Generate  summary
        """
        summary = f"{len(self.packets)} paquets capturés sur {self.interface}.\n Protocoles {self.all_protocols}\n"

        if self.alerts:
            summary += f"{len(self.alerts)} tentative(s) d'attaque détectée(s) :\n"
            for alert in self.alerts:
                summary += f"- {alert.attack} ({alert.protocol}) depuis {alert.ip} / {alert.mac}\n"
        else:
            summary += "Aucun trafic illégitime détecté, tout va bien.\n"

        return summary
