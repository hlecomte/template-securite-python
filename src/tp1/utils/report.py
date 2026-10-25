from asyncio import protocols

from tp1.utils import capture
#from tp1.utils.capture import Capture
import io
from fpdf import FPDF
from fpdf.enums import XPos, YPos
import matplotlib.pyplot as plt
from tp1.utils.config import logger


class Report:
    def __init__(self, capture: Capture, filename: str):
        self.capture = capture
        self.filename = filename
        self.title = "RAPPORT TRAFFIC INTERNET"
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concatenate report content
        :return:
        """
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 20)
        pdf.cell(0, 12, self.title, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)

        if self.array:
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Tableau des protocoles", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 11)
            with pdf.table(col_widths=(50, 25, 25), text_align=("LEFT", "RIGHT", "RIGHT")) as table:
                header = table.row()
                for title in ("Protocole", "Paquets", "Pourcentage"):
                    header.cell(title)
                for protocol, count, percent in self.array:
                    row = table.row()
                    row.cell(protocol)
                    row.cell(str(count))
                    row.cell(f"{percent:.1f} %")
            pdf.ln(5)

        if self.graph is not None:
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Graphique", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.graph.seek(0)
            pdf.image(self.graph, w=pdf.epw)

        return pdf

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename:
        :return:
        """
        logger.info("Saving report in {}".format(filename))

        pdf = self.concat_report()
        pdf.output(self.filename)


    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        protocols = self.capture.summary["protocols"]

        if param == "graph":

            logger.info("Graph génération")

            plt.figure(figsize=(8, 4))
            plt.bar(protocols.keys(), protocols.values())
            plt.title("Nombre de paquets par protocole")
            plt.xlabel("Protocole")
            plt.ylabel("Paquets")
            plt.xticks(rotation=45)
            plt.tight_layout()

            graph = io.BytesIO()
            plt.savefig(graph)
            plt.close()
            self.graph = graph

        elif param == "array":

            logger.info("Array génération")

            total = sum(protocols.values())
            array = []
            for key in protocols.keys():
                percent = protocols[key] / total * 100 if total else 0
                array.append((key, protocols[key], percent))
            array.append(("Total", total, 100.0 if total else 0))
            self.array = array
