import hashlib
import math
import magic
import re
from collections import Counter

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
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""

        patterns = {
            "domains": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            "ips": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "urls": r"https?://[^\s\"'<>]+",
            "mutex": r"\b(?:Global|Local)\\\S+",
            "registry": r"\b(?:HKEY_\w+|HKLM|HKCU)\\[^\"'\r\n]+",
        }
        extensions = {"com", "net", "org", "info", "biz", "io", "co", "xyz", "top", "online","site", "club", "app", "dev", "cloud", "live", "pw", "cc", "su","fr", "de", "uk", "us", "ru", "cn", "jp", "br", "in", "it", "es","nl", "be", "ch", "ca", "au", "pl", "ua", "kr", "tk", "ir","test"}

        strings = self._extract_strings()

        iocs = {"iocs":{}}
        for nom, regex in patterns.items():
            resultats = set()
            for s in strings:
                resultats.update(re.findall(regex, s))
            iocs["iocs"][nom] = sorted(resultats)

        iocs["iocs"]["domains"] = [
            d for d in iocs["iocs"]["domains"]
            if d.split(".")[-1].lower() in extensions
        ]
        return iocs

    def _extract_strings(self, min_len=4) -> list:
        """
            Extract strings.
            :return: str
        """
        chaines = re.findall(rb"[ -~]{%d,}" % min_len, self.data)
        return [c.decode() for c in chaines]

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""

