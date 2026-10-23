from unittest import result

from six import assertRaisesRegex

from src.tp1.utils.lib import hello_world, choose_interface, choose_report_file
from src.tp1.utils.lib import create_parser ,parse_arguments
from src.tp1.utils.lib import find_default_interface


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string

def test_parssing_interface():
    #When
    parser = create_parser()
    result = parser.parse_args(["--iface", "eth0"])

    #Then
    assert result.iface == "eth0"

def test_parssing_filename():
    #When
    parser = create_parser()
    result = parser.parse_args(["--out", "report.json"])

    #Then
    assert result.out == "report.json"

def test_choose_interface_when_iface():
    #When
    parser = create_parser()
    parser.parse_args(["--iface", "eth0"])
    result = choose_interface()

    #Then
    assert result == "eth0"

def test_choose_interface_when_pcap():
    #When
    parser = create_parser()
    args = parser.parse_args(["--pcap", "./foo.pcap"])
    result = choose_interface(args)

    # Then
    assert result == "./foo.pcap"

def test_choose_interface_when_no_interface():
    #When
    result = choose_interface()

    #Then
    assert result == "wlp6s0"

def test_choose_report_file():
    # When
    parser = create_parser()
    args = parser.parse_args(["--out", "fox.json"])
    result = choose_report_file(args)

    # Then
    assert result == "fox.json"

def test_choose_report_file_when_no_report_file():
    #When
    filename = choose_report_file()

    #Then
    assert filename == "report.json"

def test_passer_argument():
    #When
    parser = create_parser()
    args = parser.parse_args(["--iface", "eth0"])
    result = parse_arguments(args)

    #Then
    assert result.iface == "eth0"

def test_find_default_interface():
    #When
    result = find_default_interface()

    #Then
    assert result == "wlp6s0"