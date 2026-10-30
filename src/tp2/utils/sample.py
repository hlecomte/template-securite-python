import hashlib
import math
import magic
import re
from collections import Counter
import lief

from tp2.utils.config import logger


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
        metadata["size"] = len(self.data)
        metadata["entropy"] = self.shannon_entropy()
        metadata["file_type"] = magic.from_buffer(self.data)


        logger.info("Done.")
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

        TEXT = [s.decode("ascii") for s in re.findall(rb"[\x20-\x7e]{4,}", self.data)]
        EXTENTION = {
            "com", "net", "org", "info", "biz", "io", "co", "xyz", "top", "online",
            "site", "club", "app", "dev", "cloud", "live", "pw", "cc", "su",
            "fr", "de", "uk", "us", "ru", "cn", "jp", "br", "in", "it", "es",
            "nl", "be", "ch", "ca", "au", "pl", "ua", "kr", "tk", "ir", "test"
        }
        EXTENTION_RE = "|".join(sorted(EXTENTION, key=len, reverse=True))

        DOMAIN = re.compile(rf"\b(?:[a-z0-9-]+\.)+(?:{EXTENTION_RE})\b", re.I)
        IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        URL = re.compile(r"https?://[^\s\"'<>]+")
        MUTEXT = re.compile(r"\b(?:Global|Local)\\\S+")
        REGISTRY = re.compile(r"\b(?:HKEY_\w+|HKLM|HKCU)\\[^\"'\r\n]+")




        iocs = {"iocs": { "domains": [], "ips": [], "urls": [], "mutex": [], "registry": []}}

        for text in TEXT:
            if re.findall(DOMAIN, text):
                iocs["iocs"]["domains"].extend(re.findall(DOMAIN, text))
            if re.findall(IPV4, text):
                iocs["iocs"]["ips"].extend(re.findall(IPV4, text))
            if re.findall(URL, text):
                iocs["iocs"]["urls"].extend(re.findall(URL, text))
            if re.findall(MUTEXT, text):
                iocs["iocs"]["mutex"].extend(re.findall(MUTEXT, text))
            if re.findall(REGISTRY, text):
                iocs["iocs"]["registry"].extend(re.findall(REGISTRY, text))

        unique_domains = []
        for domain in iocs["iocs"]["domains"]:
            if domain not in unique_domains:
                unique_domains.append(domain)

        iocs["iocs"]["domains"] = unique_domains

        return iocs


    def extract_flag(self) -> dict:
        """
        Extract flag from self.data

        :return: flag
        """
        TEXT = [s.decode("ascii") for s in re.findall(rb"[\x20-\x7e]{4,}", self.data)]
        FLAG = re.compile(r"ESGI\{[a-zA-Z0-9]+_[0-9a-f]+\}")

        flag = {"flag" : ""}

        for text in TEXT:
            if re.findall(FLAG, text):
                flag["flag"] = re.findall(FLAG, text)[0]

        return flag



    def parse_binary(self) -> dict:
        """
            imports / sections via lief (si PE/ELF).
            :retunr: dict
        """
        binary = lief.parse(self.data)
        imports = {"imports" : []}
        for imp in binary.imported_functions:
            imports["imports"].append(imp.name)

        #for sec in binary.sections:
        #    imports["imports"].append(f"{sec.name} {round(sec.entropy, 2)}")

        return imports
