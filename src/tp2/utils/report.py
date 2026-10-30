from fpdf import FPDF
from pathlib import Path
import json

OUT_PATH = Path(__file__).parent.parent / "report"

class Report:
    def __init__(self, result: dict, out_path: str = OUT_PATH ) -> None:
        self.result = result
        self.out_path = out_path


    def generate_pdf(self) -> None:
        """Rapport PDF lisible (fpdf2)."""
        return None





    def generate_json(self) -> None:
        """Fichier JSON lisible."""

        for sha256, analyse in self.result.items():
            chemin = f"{self.out_path}/{analyse["file"]}.triage.json"
            sortie = {key: value for key, value in analyse.items() if key != "file"}
            with open(chemin, "w", encoding="utf-8") as f:
                json.dump(sortie, f, indent=4, ensure_ascii=False)
