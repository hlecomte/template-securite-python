from unittest import result

from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner
from os import listdir
import json

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
        report = {}
        suspect_file = [f for f in listdir(self.path) if f.endswith(".bin")]
        for file in suspect_file:
            sample = Sample(f"{self.path}/{file}")
            logger.info(f"Triage de {self.path}/{file}({len(sample.data)} octets)")

            logger.info(f"Get {self.path}/{file} metadata")

            meta = sample.get_file_metadata()

            logger.info(f"Done")
            logger.info(f"Extract {self.path}/{file} iocs")
            iocs = sample.extract_iocs()

            logger.info(f"Done")
            logger.info(f"Sample {self.path}/{file} binary")

            bininfo = sample.parse_binary()

            logger.info(f"Done")
            logger.info(f"Get {self.path}/{file} Flag")

            flag = sample.extract_flag()

            logger.info(f"Done")
            logger.info(f"The flag is {flag}")
            logger.info(f"Malware scanning {self.path}/{file}...")

            matches = self.scanner.scan(sample.data)

            logger.info(f"Done")
            logger.info(f"For {self.path}/{file} we have {len(matches)} matches")

            presentation = {}
            presentation.update(meta)
            presentation.update(bininfo)
            presentation.update(iocs)
            presentation.update(flag)
            presentation["yara_matches"] = flag

            summary = json.dumps(presentation)
            verdict = self.llm.triage(summary)
            result = json.dumps(presentation.update(verdict))
            report.update({presentation["metadata"]["sha256"] : result})

        return report

