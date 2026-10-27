import unittest
from src.tp2.utils.sample import Sample

class MyTestCase(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)  # add assertion here


if __name__ == '__main__':
    unittest.main()

def test_Sample_init():

    # When
    sample = Sample("/home/hlecomte/PycharmProjects/template-securite-python/src/tp2/suspectfile/sample1_dropper.bin")

    # Then
    assert sample.path == "/home/hlecomte/PycharmProjects/template-securite-python/src/tp2/suspectfile/sample1_dropper.bin"

def test_get_file_metadata():
    #Given
    sample = Sample("/home/hlecomte/PycharmProjects/template-securite-python/src/tp2/suspectfile/sample1_dropper.bin")

    # When
    metadata = sample.get_file_metadata()

    assert metadata == {'sha256': '77604f4421c2356ae44ac4b3a7fc8be87e03f92e22fefecffca552847adebfc7', 'md5': 'dab0f74f4f4b1e938fcd769e8a602d6d', 'taille': 43900, 'file_type': 'ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)', 'entropy': 4.800521188717971}

def test_extract_iocs():
    #Given
    sample = Sample("/home/hlecomte/PycharmProjects/template-securite-python/src/tp2/suspectfile/sample1_dropper.bin")

    #When
    iocs = sample.extract_iocs()

    assert iocs == {'iocs': {'domains': ['c2-62d30101.example.test', 'gnu.org', 'translationproject.org', 'www.gnu.org'], 'ips': ['185.214.153.19'], 'urls': ['http://c2-62d30101.example.test/gate.php', 'https://gnu.org/licenses/gpl.html', 'https://translationproject.org/team/', 'https://www.gnu.org/gethelp/', 'https://www.gnu.org/software/coreutils/'], 'mutex': ['Global\\m3fd57966'], 'registry': ['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svcda6483']}}