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

def parse_arguments(args_test=None):
    """
    Parse the command line arguments

    :return: arguments parsed
    """
    if args_test is not None:
        return args_test

    args = create_parser()

    return args.parse_args()

def choose_interface(args_test=None) -> str:
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
    elif args.pcap is not None:
        interface = args.pcap
    else:
        interface = find_default_interface()

    return interfaces

def choose_report_file(args_test=None) -> str:
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

def find_default_interface() -> str:
    route = "/proc/net/route"
    with open(route) as f:
        for line in f.readlines():
            try:
                iface, dest, _, flags, _, _, _, _, _, _, _, =  line.strip().split()
                if dest != '00000000' or not int(flags, 16) & 2:
                    continue
                return iface
            except:
                continue

