import argparse
import subprocess


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the threat-analysis pipeline over application logs, tshark CSV exports, or packet captures."
    )
    parser.add_argument(
        "--input",
        default="data/raw/access.log",
        help="Raw source file to ingest. Supports app logs, tshark CSV exports, and pcap/pcapng files.",
    )
    parser.add_argument(
        "--format",
        choices=["auto", "app_log", "tshark_csv", "pcap"],
        default="auto",
        help="Source format. Defaults to auto-detection.",
    )
    return parser.parse_args()


def run_step(message: str, command: list[str]):
    print(message)
    subprocess.run(command, check=True)


def main():
    args = parse_args()

    run_step(
        "->Parsing and normalizing events",
        [
            "python3",
            "src/parse.py",
            "--input",
            args.input,
            "--format",
            args.format,
        ],
    )

    run_step(
        "->Generating features",
        ["python3", "src/feature.py"],
    )

    run_step(
        "->Running anomaly detection",
        ["python3", "src/model.py"],
    )

    run_step(
        "->Generating threat report",
        ["python3", "src/report.py"],
    )

    print("\nPipeline execution complete.")


if __name__ == "__main__":
    main()
