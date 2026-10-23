from tp1.utils.capture import Capture
import matplotlib

class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "TITRE DU RAPPORT"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concatenate report content
        :return:
        """
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph

        return content

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename:
        :return:
        """
        final_content = self.concat_report()
        with open(self.filename, "w") as report:
            report.write(final_content)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        matplotlib.use("Agg")
        plt = matplotlib.pyplot

        if param == "graph":
            protocols = self.capture.sort_network_protocols()

            plt.figure(figsize=(8, 4))
            plt.bar(protocols.keys(), protocols.values())
            plt.title("Nombre de paquets par protocole")
            plt.xlabel("Protocole")
            plt.ylabel("Paquets")
            plt.xticks(rotation=45)
            plt.tight_layout()

            graph = "graph.png"
            plt.savefig(graph)
            plt.close()
            self.graph = graph

        elif param == "array":
            array = [["Attaque", "Protocole", "IP", "MAC"]]
            for alert in self.capture.alerts:
                array.append([alert["attack"], alert["protocol"], alert["ip"], alert["mac"]])

            if len(array) == 1:
                array.append(["Aucune attaque", "-", "-", "-"])
            self.array = array
