from collections import Counter
import yara
from urllib.parse import unquote_plus
from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import sniff, rdpcap, Raw, IP, IPv6, Ether
from pathlib import Path


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packet = ""
        self.alerts = None

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")

        if Path(interface).is_file():
            self.packets = rdpcap(interface)
        else:
            self.packets = sniff(iface=interface, count=100)


    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        logger.info(f"Sorting network protocols")
        protocols_sorted = dict(sorted(self.packets.protocols.items(), key=lambda item: item[1], reverse=True))

        return protocols_sorted

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        counter = Counter()

        logger.info(f"Capture all protocols")

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

        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()
        self.alerts = self._attack_warning(protocols)


    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = f"{len(self.packets)} paquets capturés sur {self.interface}.\n Protocoles {self.all_protocols}\n"

        if self.alerts:
            summary += f"{len(self.alerts)} tentative(s) d'attaque détectée(s) :\n"
            for alert in self.alerts:
                summary += f"- {alert.attack} ({alert.protocol}) depuis {alert.ip} / {alert.mac}\n"
        else:
            summary += "Aucun trafic illégitime détecté, tout va bien.\n"

        return summary

    def _attack_warning(self, protocols: str):
        """

        Return attack alerts

        :returns: list attack

        """
        alerts = []
        rules = yara.compile("../rules/patern.yar")

        for pkt in self.packets:
            if not pkt.haslayer(Raw):
                pass

            clean_pkt = unquote_plus(pkt[Raw].load.decode(errors="ignore"))

        for match in rules.match(data=clean_pkt):
            alerts.append({
                "attack": match.rule,
                "protocol": f"{protocols}" if pkt.haslayer(protocols.upper()) else "Autre",
                "ip": self._get_ip(pkt),
                "mac": self._get_mac(pkt),
                "details": match.meta.get("description", ""),
            })

            return alerts

    def _get_ip(pkt):
            if pkt.haslayer(IP):
                return pkt[IP].src
            if pkt.haslayer(IPv6):
                return pkt[IPv6].src
            return None

    def _get_mac(pkt):
            return pkt[Ether].src if pkt.haslayer(Ether) else None
