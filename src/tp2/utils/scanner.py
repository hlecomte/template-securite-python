from os import listdir
import yara

from tp2.utils.config import logger


class YaraScanner:
    def __init__(self, rules_path: str = "rules/course_rules.yar") -> None:
        self.rules_path = rules_path

    def scan(self, data: bytes) -> list[str]:
        """
            Noms des règles YARA déclenchées.

            :return: list
        """
        matches = []
        rules_file = [f for f in listdir(self.rules_path) if f.endswith(".yar")]
        for file in rules_file:
            logger.info("Scanning YARA rules file: {}".format(file))
            rules = yara.compile(f"{self.rules_path}/{file}")
            for match in rules.match(data=data):
                matches.append(match.rule)

        return matches



