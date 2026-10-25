from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.lib import choose_report_file
from tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    capture = Capture()
    capture.capture_traffic()
    capture.analyse("tcp")
    # summary = capture.get_summary()

    filename = "report_volume.pdf"
    # report = Report(capture, filename, summary)
    report = Report(capture, filename)
    report.generate("graph")
    report.generate("array")
    report.save(filename)


if __name__ == "__main__":
    main()
