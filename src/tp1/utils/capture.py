import json
import yara
from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from urllib.parse import unquote_plus
from scapy.all import sniff, rdpcap, Raw
from scapy.all import IP, IPv6, Ether
from collections import Counter
from pathlib import Path

class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.all_protocols = Counter()
        self.summary = ""
        self.packets = ""
        self.alerts = None
        self.flag = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")


        if self._is_a_file(interface):
            self.packets = rdpcap(interface)
        else:
            self.packets = sniff(iface=interface, count=100)

    def sort_network_protocols(self) -> None:
        """
        Sort and return all captured network protocols
        """
        logger.info(f"Sorting network protocols")
        tmp = dict(self.all_protocols)
        self.all_protocols = dict(sorted(tmp.items(), key=lambda item: item[1], reverse=False))



    def get_all_protocols(self) -> None:
        """
        Return all protocols captured with total packets number
        """
        logger.info(f"Capture all protocols")

        for pkt in self.packets:
            for name in {layer.__name__ for layer in pkt.layers()}:
                self.all_protocols[name] += 1


    def analyse(self, protocols: str = "tcp") -> None:
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

        self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {self.all_protocols.keys()}")
        logger.debug(f"Sorted protocols: {sort}")


        self.alerts = self._attack_warning(protocols)
        self.summary = self.all_protocols
        self._gen_json_report()


    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self, all_protocols) -> None:
        """
        Generate summary

        :return: str
        """
        summary = f"{len(self.packets)} paquets capturés sur {self.interface}.\n Protocoles {self.all_protocols}\n"

        if self.alerts:
            summary += f"{len(self.alerts)} tentative(s) d'attaque détectée(s) :\n"
            for alert in self.alerts:
                summary += f"- {alert.attack} ({alert.protocol}) depuis {alert.ip} / {alert.mac}\n"
        else:
            summary += "Aucun trafic illégitime détecté, tout va bien.\n"


    def _gen_json_report(self) -> None:
        """
        Generate json alert report

        :returns: None

        """

        report = {
            "protocol" : self.all_protocols,
            "attacks"  : self.alerts
            "flag": self.flag

        }

        with open('report.json', 'w') as fichier:
            json.dump(alerts, fichier, indent=4)


    def _attack_warning(self, protocols: str):
        """

        Return attack alerts

        :returns: list attack

        """
        alerts = []
        rules_path = str(Path(__file__).resolve().parent.parent / "rules" / "patern.yar")
        rules = yara.compile(filepath=rules_path)
        protocols = protocols.upper()

        for pkt in self.packets:
            if not pkt.haslayer(Raw):
                continue

            elif not pkt.haslayer(protocols):
                continue

            charge_utile = unquote_plus(pkt[Raw].load.decode(errors="ignore"))

            for match in rules.match(data=charge_utile):
                alerts.append({
                    "attack": match.rule,
                    "protocol": f"{protocols}" if pkt.haslayer(protocols) else "Autre",
                    "ip": self._get_ip(pkt),
                    "mac": self._get_mac(pkt),
                    "details": match.meta.get("description", ""),
                })

        return alerts

    def _get_ip(self, pkt:str):
            if pkt.haslayer(IP):
                return pkt[IP].src
            if pkt.haslayer(IPv6):
                return pkt[IPv6].src
            return None

    def _get_mac(self, pkt:str):
            return pkt[Ether].src if pkt.haslayer(Ether) else None

    def _is_a_file(self, interface) -> bool:
        """
        Check if the interface is a file

        :returns: bool

        """

        if not Path.is_file(interface):
            return False
        else:
            return True

