import json
import yara
from src.tp1.utils.lib import choose_interface, choose_report_file
from tp1.utils.config import logger
from urllib.parse import unquote_plus
from scapy.all import sniff, rdpcap, Raw
from scapy.all import IP, IPv6, Ether, ARP, TCP
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
        self.patern = patern = """

private rule HTTP_Request
{
    strings:
        // Pas de \S+ pour l'URL : après unquote_plus elle peut contenir des espaces
        $methode = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) [^\r\n]+ HTTP\/[0-9.]+\r?\n/

    condition:
        $methode at 0
}


rule SQL_Injection
{
    meta:
        description = "Injection SQL : UNION SELECT, tautologie, requête empilée ou injection temporelle"
        category    = "SQL Injection"
        severity    = "high"

    strings:
        // Motifs forts : un seul suffit
        $union    = /union(\s|\/\*[^*]*\*\/)+(all(\s|\/\*[^*]*\*\/)+)?select\s/ nocase
        $stacked  = /;\s*(drop|truncate|alter)\s+table\s/ nocase
        $sleep    = /(sleep|pg_sleep)\s*\(\s*\d+\s*\)/ nocase
        $bench    = /benchmark\s*\(\s*\d+\s*,/ nocase
        $waitfor  = /waitfor\s+delay\s+'/ nocase
        $tauto    = /'\s*(or|and)\s+'?(\w+)'?\s*=\s*'?\w+/ nocase
        $tauto_n  = /\s(or|and)\s+\d+\s*=\s*\d+(\s|$|--|#|;)/ nocase
        $bypass   = /'\s*(--|#)(\s|&|$)/                       // admin'--  (fin de la valeur)

        // Motifs faibles : il en faut deux
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


rule XSS
{
    meta:
        description = "Cross-Site Scripting : balise ou gestionnaire d'événement JavaScript injecté dans une requête"
        category    = "XSS"
        severity    = "high"

    strings:
        $script   = /<\s*script[\s>\/]/ nocase
        $handler  = /<\s*(img|svg|body|iframe|input|video|details|a)\b[^>]*\son[a-z]+\s*=/ nocase
        $js_uri   = /(href|src|action)\s*=\s*["']?\s*javascript:/ nocase
        $js_param = /=\s*javascript:/ nocase
        $cookie   = /document\.(cookie|location|domain)/ nocase
        $iframe   = /<\s*iframe[^>]+src\s*=/ nocase

    condition:
        HTTP_Request and any of them
}


rule Path_Traversal
{
    meta:
        description = "Path traversal / LFI : remontée d'arborescence ou accès à un fichier système sensible"
        category    = "Path Traversal"
        severity    = "high"

    strings:
        $dotdot     = /(\.\.[\/\\]){2,}/
        $dotdot_enc = /(%2e%2e|\.\.)(%2f|%5c)/ nocase          // double encodage restant
        $passwd     = /\/etc\/(passwd|shadow|hosts|group)\b/
        $win        = /(boot\.ini|win\.ini|system32[\/\\])/ nocase
        $wrapper    = /(php|file|expect|zip|phar):\/\// nocase

    condition:
        HTTP_Request and any of them
}



rule Command_Injection
{
    meta:
        description = "Injection de commande : séparateur shell suivi d'une commande système"
        category    = "Command Injection"
        severity    = "critical"

    strings:
        // ;cat  |id  &&whoami  $(uname)  `wget ...`
        $chain  = /(;|\||&&|\$\(|`)\s*(cat|id|whoami|uname|ls|pwd|wget|curl|nc|ncat|bash|sh|ping|nslookup|rm|chmod|python3?|perl)(\s|$|;|\||\)|`)/
        $shell  = /\/bin\/(ba|z|da)?sh\b/
        $win    = /(cmd(\.exe)?\s*\/c|powershell(\.exe)?\s+-)/ nocase
        $revsh  = /\/dev\/tcp\/\d{1,3}(\.\d{1,3}){3}\/\d+/

    condition:
        HTTP_Request and any of them
}


rule Log4Shell
{
    meta:
        description = "Exploitation Log4Shell : expression JNDI dans les données (CVE-2021-44228)"
        category    = "RCE"
        severity    = "critical"

    strings:
        $jndi    = /\$\{\s*jndi\s*:\s*(ldap|ldaps|rmi|dns|iiop|http|nis|corba)/ nocase
        $obfusc  = /\$\{[^}]{0,30}\$\{(lower|upper|env|sys|::-)/ nocase

    condition:
        any of them
}


rule Webshell_Upload
{
    meta:
        description = "Code PHP exécutable envoyé dans une requête (upload de web shell)"
        category    = "Web Shell"
        severity    = "critical"

    strings:
        $php_tag = /<\?(php|=)/ nocase
        $exec    = /(system|exec|shell_exec|passthru|popen|proc_open|assert|eval)\s*\(/ nocase
        $b64     = /base64_decode\s*\(/ nocase
        $input   = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/

    condition:
        HTTP_Request and $php_tag and ($exec or $b64 or $input)
}


rule SSRF_Metadata
{
    meta:
        description = "SSRF : requête qui cible un service interne de métadonnées cloud"
        category    = "SSRF"
        severity    = "high"

    strings:
        $aws    = "169.254.169.254"
        $gcp    = "metadata.google.internal" nocase
        $azure  = "169.254.169.254/metadata" nocase
        $local  = /=\s*(https?|gopher|dict):\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0)/ nocase

    condition:
        HTTP_Request and any of them
}


rule Scanner_User_Agent
{
    meta:
        description = "Requête émise par un outil de scan ou d'attaque (User-Agent identifié)"
        category    = "Reconnaissance"
        severity    = "medium"

    strings:
        $ua = /\r\nUser-Agent:[^\r\n]*(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|ffuf|wfuzz|wpscan|acunetix|nessus|openvas|hydra|nuclei|w3af|burp)/ nocase

    condition:
        HTTP_Request and $ua
}



rule Cleartext_Credentials
{
    meta:
        description = "Identifiants transmis en clair (FTP, POP3, IMAP ou HTTP Basic)"
        category    = "Credentials"
        severity    = "low"

    strings:
        $ftp_pop = /^(PASS|USER) \S+\r?\n/                   // FTP et POP3
        $imap    = /^\S+ LOGIN \S+ \S+\r?\n/ nocase           // IMAP
        $basic   = /\r\nAuthorization:\s*Basic\s+[A-Za-z0-9+\/=]{4,}/ nocase

    condition:
        $ftp_pop at 0 or $imap at 0 or $basic
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
            "protocols": self.all_protocols,
            "attacks": self.alerts,
            "flag": self.flag

        }



        with open(choose_report_file(), 'w') as fichier:
            json.dump(self.summary, fichier, indent=4)



    def _attack_warning(self, protocols: str) -> None:
        """

        Return attack alerts

        :returns: list attack

        """

        def _attack_warning(self, protocols: str):
            """

            Return attack alerts

            :returns: list attack

            """
            alerts = []
            #rules_path = str(Path(__file__).resolve().parent.parent / "rules" / "patern.yar")
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

            return alerts


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


