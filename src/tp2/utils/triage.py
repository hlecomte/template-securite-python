from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner
from os import listdir

class Triage:
    def __init__(self, path: str, rules_path: str, out_path: str,  backend: str) -> None:
        self.path = path
        self.rules_path = rules_path
        self.out_path = out_path
        self.backend = backend
        self.scanner = YaraScanner(rules_path)
        self.llm = LLMTriage(backend)

    def run(self) -> dict:
        """
        Sort the infected files from a folder

        :return: dict

        """
        suspect_file = [f for f in listdir(self.path)]
        for file in suspect_file:
            sample = Sample(f"{self.path}/{file}")
            logger.info(f"Triage de {self.path}/{file}({len(sample.data)} octets)")

            meta = sample.get_file_metadata()
            iocs = sample.extract_iocs()
            bininfo = sample.parse_binary()
            flag = sample.extract_flag()
            # matches = self.scanner.scan(sample.data)
            # summary = json.dumps({"meta": meta, "iocs": iocs, "yara": matches, "bin": bininfo})
            # verdict = self.llm.triage(summary)

        return {}
