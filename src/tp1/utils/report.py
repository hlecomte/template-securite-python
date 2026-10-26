from tp1.utils.capture import Capture
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

    def concat_report(self) -> FPDF:
        """
        Concatenate report content
        :return: pdf document
        """
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 20)
        pdf.cell(0, 10, self.title)
        pdf.ln(20)

        pdf.set_font("Helvetica", "", 11)
        for protocol, count, percent in self.array:
            pdf.cell(60, 8, protocol, border=1)
            pdf.cell(40, 8, str(count), border=1)
            pdf.cell(40, 8, str(round(percent, 1)) + " %", border=1)
            pdf.ln()

        if self.graph:
            pdf.ln(10)
            self.graph.seek(0)
            pdf.image(self.graph, w=180)

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
