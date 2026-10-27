import json
import yara
from src.tp1.utils.lib import choose_interface, choose_report_file
from tp1.utils.config import logger
from urllib.parse import unquote_plus
from scapy.all import sniff, rdpcap, Raw
from scapy.all import IP, IPv6, Ether, ARP, TCP
from collections import Counter, defaultdict
from pathlib import Path


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.all_protocols = Counter()
        self.summary = ""
        self.packets = ""
        self.alerts = []
        self.flag = ""
        self.patern = r"""

private rule HTTP_Request
{
    strings:
        $methode = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) [^\r\n]+ HTTP\/[0-9.]+\r?\n/

    condition:
        $methode at 0
}


rule sql_injection
{

    strings:

        $union    = /union(\s|\/\*[^*]*\*\/)+(all(\s|\/\*[^*]*\*\/)+)?select\s/ nocase
        $stacked  = /;\s*(drop|truncate|alter)\s+table\s/ nocase
        $sleep    = /(sleep|pg_sleep)\s*\(\s*\d+\s*\)/ nocase
        $bench    = /benchmark\s*\(\s*\d+\s*,/ nocase
        $waitfor  = /waitfor\s+delay\s+'/ nocase
        $tauto    = /'\s*(or|and)\s+'?(\w+)'?\s*=\s*'?\w+/ nocase
        $tauto_n  = /\s(or|and)\s+\d+\s*=\s*\d+(\s|$|--|#|;)/ nocase
        $bypass   = /'\s*(--|#)(\s|&|$)/                       // admin'--  (fin de la valeur)


        $schema   = "information_schema" nocase
        $comment  = /'\s*(--|#|\/\*)/
        $concat   = /(concat|group_concat|char)\s*\(/ nocase
        $version  = /@@version|version\s*\(\s*\)/ nocase

    condition:
        HTTP_Request and
        (
            any of ($union, $stacked, $sleep, $bench, $waitfor, $tauto, $tauto_n, $bypass) or
            2 of ($schema, $comment, $concat, $version)
        )
}

rule ARP_Reply 
{

    condition: uint16be(12) == 0x0806 and uint16be(20) == 2 
 
 }

"""

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


    def get_summary(self) -> str:s
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
            "protocols": self.all_protocols,
            "attacks": self.alerts,
            "flag": self.flag

        }



        with open(choose_report_file(), 'w') as fichier:
            json.dump(self.summary, fichier, indent=4)




    def _attack_warning(self, protocols: str):
        """

        Return attack alerts

        :returns: list attack

        """

        self._detect_scan_port(protocols)
        self._detect_arp_spoofing()
        self._detect_SQL_injection(protocols)

    def _detect_scan_port(self, protocols: str = "tcp", seuil: int = 15):
        """
        Detect scan port : une IP qui envoie des SYN (ou NULL/FIN/Xmas)
        vers au moins `seuil` ports différents.
        """
        protocols = protocols.upper()
        registre_connexions = set()

        for pkt in self.packets:
            if not pkt.haslayer(IP) or not pkt.haslayer(protocols):
                continue

            if protocols == "TCP" and int(pkt[TCP].flags) not in (0x02, 0x00, 0x01, 0x29):
                continue
            mac_src = pkt[Ether].src if pkt.haslayer(Ether) else None
            registre_connexions.add((pkt[IP].src, mac_src, pkt[protocols].dport))

        nb_ports = Counter((ip_src, mac_src) for ip_src, mac_src, _ in registre_connexions)

        for (ip_src, mac_src), occurence_port in nb_ports.items():
            if occurence_port >= seuil:
                self.alerts.append({
                    "type": "port_scan",
                    "attacker": ip_src
                })

    def _detect_arp_spoofing(self):
        """
        Detect arp spoofing : une même IP annoncée par plusieurs MAC.
        """
        arp_table = defaultdict(Counter)

        for pkt in self.packets:
            if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
                continue
            arp_table[pkt[ARP].psrc][pkt[ARP].hwsrc] += 1

        for ip_usurpee, macs in arp_table.items():
            if len(macs) > 1:
                mac_attaquant, _ = macs.most_common(1)[0]
                self.alerts.append({
                    "type": "arp_spoofing",
                    "attacker": mac_attaquant,
                })

    def _detect_SQL_injection(self, protocols: str):

        """

        Detecte SQL Injection

        :return:

        """

        rules = yara.compile(source=self.patern)
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
        return Path(interface).is_file


