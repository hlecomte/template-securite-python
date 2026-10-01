from src.tp1.utils.lib import hello_world, choose_interface, choose_file


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

def test_when_choose_file_then_return_file():
    # When
    result = choose_file()

    # Then
    assert result == ""