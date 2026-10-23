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

def parse_arguments(args_test):
    """
    Parse the command line arguments

    :return: arguments parsed
    """
    if args_test is not None:
        return args_test

    args = create_parser()

    return args.parse_args()

def choose_interface(args_test) -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """

    if args_test is not None:
        if args_test.iface is not None:
            interface = args_test.iface
        else:
            interface = args_test.pcap

        return interface

    args = parse_arguments()

    if args.iface is not None:
        interface = args.iface
    else:
        interface = args.pcap

    return interface

def choose_report_file(args_test) -> str:
    """
    Returns the name of the output report

    :return: report file name
    """
    if args_test is not None:

        filename = args_test.out
        return filename

    args = parse_arguments()

    filename = args.out

    return filename
