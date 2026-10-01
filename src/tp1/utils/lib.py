import argparse

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
    parser =argparse.ArgumentParser(description="Choisi l'interface pour sniffer")
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