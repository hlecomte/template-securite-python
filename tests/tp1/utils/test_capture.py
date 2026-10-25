from unittest.mock import patch
from src.tp1.utils.capture import Capture
from collections import Counter

def test_capture_init():
    # When
    capture = Capture()

    # Then
    assert capture.interface == '/home/hlecomte/PycharmProjects/template-securite-python/src/tp1/Capture.pcap'
    assert capture.summary == ""


def test_given_capture_when_capture_traffic_then_interface_is_set():
    # Given
    capture = Capture()

    # When
    capture.capture_traffic()

    # Then
    # This is a minimal test since the method doesn't do much yet
    assert capture.interface == '/home/hlecomte/PycharmProjects/template-securite-python/src/tp1/Capture.pcap'

def test_get_all_protocols():
    # Given
    capture = Capture()
    capture.capture_traffic()

    # When
    result = capture.get_all_protocols()

    # Then
    assert capture.all_protocols == Counter({'Ether': 143, 'IP': 123, 'TCP': 95, 'ARP': 20, 'ICMP': 16, 'Raw': 13, 'UDP': 12, 'DNS': 12})
    assert result == None  # Method currently returns None

def test_sort_network_protocols():
    # Given
    capture = Capture()
    capture.capture_traffic()
    capture.get_all_protocols()

    # When
    result = capture.sort_network_protocols()

    # Then
    assert capture.all_protocols == {'DNS': 12, 'UDP': 12, 'Raw': 13, 'ICMP': 16, 'ARP': 20, 'TCP': 95, 'IP': 123, 'Ether': 143}
    assert result == None # Method currently returns None



def test_analyse():
    # Given
    capture = Capture()

    # When
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    # Then
    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"

def test_attack_warning():
    # Given
    capture = Capture()
    capture.capture_traffic()

    # When
    capture._attack_warning("tcp")

    # Then
    assert capture.alerts == []

def test_annalyse():
    # Given
    capture = Capture()
    capture.capture_traffic()

    # When
    capture.analyse("tcp")

    # Then
    assert capture.summary == {'summary': {'DNS': 12, 'UDP': 12, 'Raw': 13, 'ICMP': 16, 'ARP': 20, 'TCP': 95, 'IP': 123, 'Ether': 143}, 'alerts': []}

def test_get_summary():
    # Given
    capture = Capture()
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


def test_gen_summary():
    # Given
    capture = Capture()

    # When
    result = capture._gen_summary()

    # Then
    assert result == ""  # Method currently returns empty string


