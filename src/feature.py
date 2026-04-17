import argparse
import re
from urllib.parse import unquote

import pandas as pd

SQLI_PATTERN = re.compile(
    r"(?:union(?:\s|%20)+select|select(?:\s|%20)+.+from|or(?:\s|%20)+1=1|"
    r"(?:'|%27)\s*(?:or|and)\s*(?:'|%27)?\d+=\d+|sleep\s*\(|benchmark\s*\(|"
    r"information_schema|--|/\*|\*/|xp_cmdshell|drop(?:\s|%20)+table)",
    re.IGNORECASE,
)
RECON_PATTERN = re.compile(
    r"(?:\.env|wp-admin|wp-login|phpmyadmin|admin|backup|config|"
    r"\.git|server-status|robots\.txt|sitemap\.xml|\.sql|\.bak|"
    r"/api/|/debug|/console|/actuator|/manage)",
    re.IGNORECASE,
)


def parse_args():
    parser = argparse.ArgumentParser(description="Generate per-IP threat features.")
    parser.add_argument("--input", default="data/processed/logs.csv", help="Normalized event CSV")
    parser.add_argument("--output", default="data/processed/features.csv", help="Feature CSV")
    return parser.parse_args()


def normalize_path(value):
    path = unquote(str(value or ""))
    return path.strip()


def normalize_timestamp(series: pd.Series) -> pd.Series:
    parsed = pd.to_datetime(series, format="%Y-%m-%d %H:%M:%S,%f", errors="coerce")
    unresolved = parsed.isna()
    if unresolved.any():
        fallback = pd.to_datetime(series[unresolved], format="mixed", utc=True, errors="coerce")
        parsed.loc[unresolved] = fallback.dt.tz_localize(None)
    return parsed


def join_unique(values: pd.Series) -> str:
    unique_values = sorted({str(value).strip() for value in values if str(value).strip()})
    return ",".join(unique_values)


def main():
    args = parse_args()
    df = pd.read_csv(args.input)

    df = df.dropna(subset=["timestamp", "ip", "method", "path"])
    df["timestamp"] = normalize_timestamp(df["timestamp"])
    df["status"] = pd.to_numeric(df.get("status", 0), errors="coerce").fillna(0).astype(int)
    df["source"] = df.get("source", "unknown").fillna("unknown").astype(str)
    df["host"] = df.get("host", "").fillna("").astype(str)
    df["user_agent"] = df.get("user_agent", "").fillna("").astype(str)
    df["path"] = df["path"].map(normalize_path)
    df = df.dropna(subset=["timestamp"])

    df["is_failed"] = df["status"] == 401
    df["is_error"] = df["status"] >= 400
    df["is_sqli"] = df["path"].str.contains(SQLI_PATTERN, na=False)
    df["is_recon"] = df["path"].str.contains(RECON_PATTERN, na=False)

    grouped = df.groupby("ip")

    features = grouped.agg(
        total_requests=("status", "count"),
        failed_requests=("is_failed", "sum"),
        error_requests=("is_error", "sum"),
        distinct_paths=("path", "nunique"),
        distinct_hosts=("host", lambda x: x.replace("", pd.NA).dropna().nunique()),
        sqli_attempts=("is_sqli", "sum"),
        recon_attempts=("is_recon", "sum"),
        sources=("source", join_unique),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        sample_user_agents=("user_agent", join_unique),
    ).reset_index()

    features["duration"] = (features["last_seen"] - features["first_seen"]).dt.total_seconds()
    features["duration"] = features["duration"].clip(lower=1)
    features["request_rate"] = features["total_requests"] / features["duration"]
    features["failed_ratio"] = features["failed_requests"] / features["total_requests"]
    features["error_ratio"] = features["error_requests"] / features["total_requests"]
    features["path_diversity"] = features["distinct_paths"] / features["total_requests"]

    features = features[
        [
            "ip",
            "sources",
            "total_requests",
            "failed_requests",
            "error_requests",
            "distinct_paths",
            "distinct_hosts",
            "sqli_attempts",
            "recon_attempts",
            "failed_ratio",
            "error_ratio",
            "path_diversity",
            "request_rate",
            "sample_user_agents",
        ]
    ]

    features.to_csv(args.output, index=False)

    print("Features generated successfully.")
    print(features)


if __name__ == "__main__":
    main()
