import argparse

from tp2.utils.report import Report
from tp2.utils.triage import Triage


def main() -> None:
    """
    Main function

    :return: None

    """
    ap = argparse.ArgumentParser(prog='tp2', description='Malware Analysis')
    ap.add_argument("-s", "--sample", type=str, help="Specifies path to suspicious files folder", required=True)
    ap.add_argument("-r", "--rules", type=str, help="Specifies path to yara rules folder", required=True)
    ap.add_argument("-o", "--out", type=str, help="Specifies path to report folder", required=True)
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter",type=str, help="Specifies the llm used")
    args = ap.parse_args()

    triage = Triage(args.sample, args.rules, args.out, args.llm)
    result = triage.run()

    # A modifier pour boucle d'enregistrement dans un dossier des rapports
    report = Report(result)
    report.generate_pdf(f"{args.sample}.triage.pdf")
    report.generate_json(f"{args.sample}.triage.json")


if __name__ == "__main__":
    main()
