from collections import Counter

from _testcapi import _test_structmembersType_NewAPI

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import sniff, rdpcap
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
        summary = ""
        return summary

    def _attack_warning(self, protocols: str):
