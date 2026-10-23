from unittest import result

from src.tp1.utils.lib import hello_world, choose_interface, parse_arguments
from tp1.utils.lib import create_parser


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


def test_when_choose_interface_then_return_empty_string():
    # When
    result = choose_interface()

    # Then
    assert result == ""

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

