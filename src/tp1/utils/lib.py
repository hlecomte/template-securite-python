import argparse

from elftools.elf import descriptions


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"

def create_parser():
    """
    Create the argument parser

    :return: argument parser

    """
    parser = argparse.ArgumentParser(prog="tp1", description="Network analysis")
    parser.add_argument("--iface", type=str, help="Specifies the interface to sniff")
    parser.add_argument("--pcap", type=str, help="PCAP file to inspect")
    parser.add_argument("--out", type=str, help="Returns the name of the output report")

    return parser

def parse_arguments():
    """
    Parse the command line arguments

    :return: arguments parsed
    """

    args = create_parser()

    return args.parse_args()

def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """

    args = parse_arguments()

    if args.iface is not None:
        interface = args.iface
    else:
        interface = args.pcap

    return interface

def choose_report_file() -> str:
    """
    Returns the name of the output report

    :return: report file name
    """

    args = parse_arguments()

    filename = args.out

    return filename
