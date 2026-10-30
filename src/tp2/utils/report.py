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


        for sha256, analyse in self.result.items():
            pdf = FPDF()
            pdf.add_page()

            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 10, "Rapport de triage", new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Helvetica", size=10)
            for key, value in analyse.items():
                texte = f"{key} : {json.dumps(value, ensure_ascii=False)}"
                texte = texte.encode("latin-1", "replace").decode("latin-1")
                pdf.multi_cell(0, 6, texte, new_x="LMARGIN", new_y="NEXT")

            pdf.output(f"{self.out_path}/{analyse["file"]}.triage.pdf")



    def generate_json(self) -> None:
        """Fichier JSON lisible."""

        for sha256, analyse in self.result.items():
            chemin = f"{self.out_path}/{analyse["file"]}.triage.json"
            sortie = {key: value for key, value in analyse.items() if key != "file"}
            with open(chemin, "w", encoding="utf-8") as f:
                json.dump(sortie, f, indent=4, ensure_ascii=False)
