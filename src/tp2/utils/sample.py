import hashlib
import math
import magic
import re
from collections import Counter
import lief

class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = open(path, "rb").read()

    def get_file_metadata(self) -> dict:
        """
            sha256, md5, taille, type de fichier, entropie de Shannon.
            :return: dict
        """
        metadata = {}
        metadata["sha256"] = hashlib.sha256(self.data).hexdigest()
        metadata["md5"] = hashlib.md5(self.data).hexdigest()
        metadata["taille"] = len(self.data)
        metadata["file_type"] = magic.from_buffer(self.data)
        metadata["entropy"] = self.shannon_entropy()

        return metadata

    def shannon_entropy(self) -> float:
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def extract_iocs(self) -> dict:
        """
        Extract iocs from self.data

        :returns: dict

        """
        TEXT = re.findall(rb"[\x20-\x7e]{4,}", self.data)

        DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
        IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        URL = re.compile(r"https?://[^\s\"']+")
        MUTEXT = re.compile(r"\b(?:Global|Local)\\\S+")
        REGISTRY = re.compile(r"\b(?:HKEY_\w+|HKLM|HKCU)\\[^\"'\r\n]+")

        iocs = {"iocs": { "domains": [], "ips": [], "urls": [], "mutex": [], "registry": []}}

        for text in TEXT:
            if re.findall(DOMAIN, text):
                iocs["iocs"]["domains"].append(text)
            if re.findall(IPV4, text):
                iocs["iocs"]["ips"].append(text)
            if re.findall(URL, text):
                iocs["iocs"]["urls"].append(text)
            if re.findall(MUTEXT, text):
                iocs["iocs"]["mutex"].append(text)
            if re.findall(REGISTRY, text):
                iocs["iocs"]["registry"].append(text)


        return iocs

    def parse_binary(self) -> dict:
        """
            imports / sections via lief (si PE/ELF).
            :retunr: dict
        """
        binary = lief.parse(self.data)
        imports = {"imports" : []}
        for imp in binary.imported_functions:
            imports["imports"].append(imp.name)

        for sec in binary.sections:
            imports["imports"].append(f"{sec.name} {round(sec.entropy, 2)}")

        return imports
