import argparse

from elftools.elf import descriptions


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"

def parse_arguments() -> list:
    """
    Parse the command line arguments

    :return: list of arguments
    """
    parser = argparse.ArgumentParser(prog="tp1", description="Network analysis")
    parser.add_argument("--iface", type=str, help="Specifies the interface to sniff")
    parser.add_argument("--pcap", type=str, help="PCAP file to inspect")
    parser.add_argument("--out", type=str, help="Returns the name of the output report")
    args = parser.parse_args()

    arguments = [args.iface, args.pcap, args.out]

    return arguments

def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """

    interface = parse_arguments()

    if interface[0] is not None:
        return interface[0]
    else:
        return interface[1]

def choose_report_file() -> str:
    """
    Returns the name of the output report

    :return: report file name
    """
    parser = argparse.ArgumentParser(prog="tp1", description="Network analysis")
