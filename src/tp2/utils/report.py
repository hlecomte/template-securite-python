from fpdf import FPDF

class Report:
    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_pdf(self) -> None:
        """Rapport PDF lisible (fpdf2)."""


        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", size=12)
        pdf.cell(0, 10, f"SHA-256 : {sha256}")
        # + tableau des IOC, matches YARA, verdict LLM, score
        pdf.output("triage.pdf")

    def generate_json(self) -> None:
        """Fichier JSON lisible."""
        raise NotImplementedError
