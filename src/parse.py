import argparse
import csv
import subprocess
from pathlib import Path

import pandas as pd

NORMALIZED_COLUMNS = [
    "timestamp",
    "ip",
    "method",
    "path",
    "status",
    "source",
    "destination_ip",
    "host",
    "user_agent",
]

DEFAULT_INPUT = "data/raw/access.log"
DEFAULT_OUTPUT = "data/processed/logs.csv"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Normalize application logs or packet captures into a shared HTTP event schema."
    )
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help="Path to the raw source file. Supports app logs, tshark CSV exports, and pcap/pcapng.",
    )
    parser.add_argument(
        "--format",
        choices=["auto", "app_log", "tshark_csv", "pcap"],
        default="auto",
        help="Input format. Defaults to auto-detection by file extension.",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help="Destination CSV for normalized events.",
    )
    return parser.parse_args()


def detect_format(path: Path, requested_format: str) -> str:
    if requested_format != "auto":
        return requested_format

    suffix = path.suffix.lower()
    if suffix in {".pcap", ".pcapng"}:
        return "pcap"
    if suffix == ".csv":
        return "tshark_csv"
    return "app_log"


def finalize_frame(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)

    for column in NORMALIZED_COLUMNS:
        if column not in df.columns:
            df[column] = ""

    df["timestamp"] = df["timestamp"].astype(str).str.strip()
    df["ip"] = df["ip"].astype(str).str.strip()
    df["method"] = df["method"].astype(str).str.upper().str.strip()
    df["path"] = df["path"].astype(str).str.strip()
    df["source"] = df["source"].astype(str).str.strip()
    df["destination_ip"] = df["destination_ip"].astype(str).str.strip()
    df["host"] = df["host"].astype(str).str.strip()
    df["user_agent"] = df["user_agent"].astype(str).str.strip()
    df["status"] = pd.to_numeric(df["status"], errors="coerce").fillna(0).astype(int)

    df = df[df["ip"] != ""]
    df = df[df["path"] != ""]

    return df[NORMALIZED_COLUMNS].sort_values("timestamp").reset_index(drop=True)


def parse_app_log(path: Path) -> pd.DataFrame:
    records = []

    with path.open("r", encoding="utf-8") as source:
        for raw_line in source:
            line = raw_line.strip()
            if not line:
                continue

            parts = line.rsplit(",", 4)
            if len(parts) != 5:
                continue

            timestamp, ip, method, request_path, status = parts
            records.append(
                {
                    "timestamp": timestamp,
                    "ip": ip,
                    "method": method,
                    "path": request_path,
                    "status": status,
                    "source": "app_log",
                    "destination_ip": "",
                    "host": "",
                    "user_agent": "",
                }
            )

    return finalize_frame(pd.DataFrame(records))


def parse_tshark_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)

    rename_map = {
        "frame.time_epoch": "timestamp",
        "ip.src": "ip",
        "ip.dst": "destination_ip",
        "http.request.method": "method",
        "http.request.full_uri": "path",
        "http.request.uri": "request_uri",
        "http.host": "host",
        "http.user_agent": "user_agent",
        "http.response.code": "status",
        "status_code": "status",
        "source_type": "source",
    }
    df = df.rename(columns=rename_map)

    if "timestamp" in df.columns:
        try:
            numeric_timestamps = pd.to_numeric(df["timestamp"], errors="coerce")
            if numeric_timestamps.notna().any():
                df["timestamp"] = pd.to_datetime(
                    numeric_timestamps,
                    unit="s",
                    utc=True,
                    errors="coerce",
                ).dt.strftime("%Y-%m-%d %H:%M:%S,%f").str[:-3]
        except Exception:
            pass

    if "path" not in df.columns and "request_uri" in df.columns:
        df["path"] = df["request_uri"]

    if "source" not in df.columns:
        df["source"] = "tshark_csv"

    return finalize_frame(df)


def run_tshark(command: list[str]) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout


def load_tshark_rows(output: str) -> list[dict[str, str]]:
    if not output.strip():
        return []
    return list(csv.DictReader(output.splitlines()))


def normalize_epoch_to_string(series: pd.Series) -> pd.Series:
    timestamps = pd.to_numeric(series, errors="coerce")
    return (
        pd.to_datetime(timestamps, unit="s", utc=True, errors="coerce")
        .dt.strftime("%Y-%m-%d %H:%M:%S,%f")
        .str[:-3]
    )


def parse_pcap(path: Path) -> pd.DataFrame:
    request_fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.user_agent",
        "http.response_in",
    ]
    response_fields = [
        "frame.number",
        "http.response.code",
        "http.request_in",
    ]

    request_command = [
        "tshark",
        "-r",
        str(path),
        "-Y",
        "http.request",
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in request_fields:
        request_command.extend(["-e", field])

    response_command = [
        "tshark",
        "-r",
        str(path),
        "-Y",
        "http.response",
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in response_fields:
        response_command.extend(["-e", field])

    request_rows = load_tshark_rows(run_tshark(request_command))
    response_rows = load_tshark_rows(run_tshark(response_command))

    requests_df = pd.DataFrame(request_rows)
    responses_df = pd.DataFrame(response_rows)

    if requests_df.empty:
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)

    requests_df = requests_df.rename(
        columns={
            "frame.number": "frame_number",
            "frame.time_epoch": "timestamp",
            "ip.src": "ip",
            "ip.dst": "destination_ip",
            "http.request.method": "method",
            "http.host": "host",
            "http.request.uri": "path",
            "http.user_agent": "user_agent",
            "http.response_in": "response_frame",
        }
    )
    requests_df["timestamp"] = normalize_epoch_to_string(requests_df["timestamp"])
    requests_df["source"] = "pcap"

    if responses_df.empty:
        requests_df["status"] = 0
        return finalize_frame(requests_df)

    responses_df = responses_df.rename(
        columns={
            "frame.number": "response_frame",
            "http.response.code": "status",
            "http.request_in": "request_frame",
        }
    )

    merged = requests_df.merge(
        responses_df[["response_frame", "status"]],
        on="response_frame",
        how="left",
    )
    if "request_frame" in responses_df.columns:
        fallback_merge = requests_df.merge(
            responses_df[["request_frame", "status"]].rename(columns={"request_frame": "frame_number"}),
            on="frame_number",
            how="left",
        )
        merged["status"] = merged["status"].fillna(fallback_merge["status"])

    merged["status"] = merged["status"].fillna(0)

    return finalize_frame(merged)


def parse_input(path: Path, source_format: str) -> pd.DataFrame:
    if source_format == "app_log":
        return parse_app_log(path)
    if source_format == "tshark_csv":
        return parse_tshark_csv(path)
    if source_format == "pcap":
        return parse_pcap(path)
    raise ValueError(f"Unsupported source format: {source_format}")


def main():
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    source_format = detect_format(input_path, args.format)

    df = parse_input(input_path, source_format)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    print(f"Parsed {len(df)} normalized events from {input_path} ({source_format}).")


if __name__ == "__main__":
    main()
