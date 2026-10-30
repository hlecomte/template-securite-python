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

    def run(self):
        report = {}

        logger.info(f"Folder {self.path} annalisys")


        suspect_file = [f for f in listdir(self.path) if f.endswith(".bin")]

        for file in suspect_file:
            sample = Sample(f"{self.path}/{file}")
            logger.info(f"Triage de {self.path}/{file}({len(sample.data)} octets)")

            presentation = {"file" : file}
            presentation.update(sample.get_file_metadata())
            presentation.update(sample.extract_iocs())
            presentation.update(sample.parse_binary())
            presentation["yara_matches"] = self.scanner.scan(sample.data)
            presentation["family_guess"] = ""
            presentation["mitre_attack"] = []
            presentation["llm_summary"] = ""
            presentation["score"] = int
            presentation.update(sample.extract_flag())


            logger.info(f"For {file} we have {len(presentation['yara_matches'])} matches")
            report[presentation["sha256"]] = presentation

        summary = json.dumps({
            sha256: {
                "size": p["size"],
                "entropy": round(p["entropy"], 2),
                "type": p["file_type"],
                "imports":p["imports"],
                "yara": p["yara_matches"],
                "iocs": p["iocs"],
            }
            for sha256, p in report.items()
        })
        logger.info(f"Envoi de {len(report)} fichier(s) au LLM en une requête")
        verdicts = json.loads(self.llm.triage(summary))

        for sha256, presentation in report.items():
            verdict = verdicts.get(sha256, {})
            presentation["family_guess"] = verdict.get("family_guess", "inconnue")
            presentation["mitre_attack"] = verdict.get("mitre_attack", [])
            presentation["llm_summary"] = verdict.get("llm_summary", "")
            presentation["score"] = verdict.get("score")

        return report
