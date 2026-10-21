import argparse
import yara

def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    parser = argparse.ArgumentParser(description="Choisi l'interface pour sniffer")
    parser.add_argument("--iface", type=str, help="selectione l'interface")

    args = parser.parse_args()

    return args.iface

def choose_file() -> str:
    """
    Return pcap file and input user choice

    :return: pcap file
    """
    parser = argparse.ArgumentParser(description="Choisi le fichier pcap à analyser")
    parser.add_argument("--pcap", type=str, help="selectione le fichier pcap")

    args = parser.parse_args()

    return args.pcap

def attack_warning() -> list[Alert]:
    """

    Returns:

    """
    rules = yara.compile(filepath="../rules/attacks.yar")
    alerts = []
    for pkt in self.packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        raw = bytes(pkt[Raw].load)
        decoded = unquote_plus(raw.decode(errors="ignore")).encode()

        try:
            matches = self.rules.match(data=decoded, timeout=2)
        except yara.TimeoutError:
            logger.warning("Analyse YARA trop longue, paquet ignoré")
            continue

        for match in matches:
            motif = match.strings[0].instances[0].matched_data if match.strings else b""
            alerts.append(Alert(
                attack=match.meta.get("description", match.rule),
                protocol=f"TCP/{pkt[TCP].dport}",
                ip=self._get_ip(pkt),
                mac=self._get_mac(pkt),
                details=f"Règle {match.rule}, motif {motif!r}",
            ))
    return alerts