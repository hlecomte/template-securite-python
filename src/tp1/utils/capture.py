import json
import yara
from pwnlib.flag import flag

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


        self._get_flag()
        self._attack_warning(protocols)
        self._gen_summary()


    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> None:
        """
        Generate summary

        :return: str
        """
        logger.info(f"{len(self.packets)} paquets capturés sur {self.interface}.\n Protocoles {self.all_protocols}\n")

        if self.alerts:
            logger.info(f"{len(self.alerts)} tentative(s) d'attaque détectée(s) :\n")
            for alert in self.alerts:
                logger.info(f"- {alert["type"]} depuis {alert["attacker"]}\n")
        else:
            logger.info("Aucun trafic illégitime détecté, tout va bien.\n")

        self.summary = {
            "protocol": self.all_protocols,
            "attacks": self.alerts,
            "flag": self.flag

        }



        with open('report.json', 'w') as fichier:
            json.dump(self.summary, fichier, indent=4)



    def _attack_warning(self, protocols: str) -> None:
        """

        Return attack alerts

        :returns: list attack

        """
        self.alerts = []
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
                self.alerts.append({
                    "type": match.rule,
                    "attacker": self._get_attacks_info(pkt)
                })


    def _get_flag(self) -> None:
        """
        Take flag in .pcap

        :return: flag

        """
        rules = yara.compile(source=r'rule Flag { strings: $f = /ESGI\{[^}\r\n]{1,200}\}/ condition: $f }')

        for pkt in self.packets:
            if not pkt.haslayer(Raw):
                continue

            charge_utile = unquote_plus(pkt[Raw].load.decode(errors="ignore"))

            for match in rules.match(data=charge_utile):
                for i in match.strings:
                    for c in i.instances:
                        self.flag = c.matched_data.decode(errors="ignore")




    def _get_attacks_info(self, pkt:str) -> str:
            if pkt.haslayer(IP):
                return pkt[IP].src
            elif pkt.haslayer(IPv6):
                return pkt[IPv6].src
            elif pkt.haslayer(Ether):
                return pkt[Ether].src
            return None

    def _is_a_file(self, interface) -> bool:
        """
        Check if the interface is a file

        :returns: bool

        """

        if not Path.is_file(interface):
            return False
        else:
            return True

