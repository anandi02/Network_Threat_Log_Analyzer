
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

# Project paths
PROJECT_DIR = Path(__file__).resolve().parent
CSV_FILE = PROJECT_DIR / "network_traffic.csv"
REPORT_FILE = PROJECT_DIR / "network_report.txt"
CHART_DIR = PROJECT_DIR / "charts"

# Basic alert threshold
CONNECTION_THRESHOLD = 5


def main():
    if not CSV_FILE.exists():
        print(f"Error: Dataset not found: {CSV_FILE}")
        return

    try:
        df = pd.read_csv(CSV_FILE)
    except (OSError, pd.errors.ParserError) as error:
        print(f"Could not read CSV: {error}")
        return

    required_columns = {
        "timestamp", "source_ip", "destination_ip",
        "protocol", "destination_port", "bytes",
        "connection_status"
    }

    if not required_columns.issubset(df.columns):
        print("Error: CSV is missing required columns.")
        print("Required:", ", ".join(sorted(required_columns)))
        return

    if df.empty:
        print("The CSV contains no network records.")
        return

    # Clean and prepare the data
    df["source_ip"] = df["source_ip"].astype("string").str.strip()
    df["destination_ip"] = (
        df["destination_ip"].astype("string").str.strip()
    )
    df["protocol"] = df["protocol"].astype("string").str.upper().str.strip()
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce")
    df["destination_port"] = pd.to_numeric(
        df["destination_port"], errors="coerce"
    )

    df = df.dropna(
        subset=[
            "source_ip", "destination_ip",
            "protocol", "bytes", "destination_port"
        ]
    )

    if df.empty:
        print("No valid network records remain after cleaning.")
        return

    # Analyze network traffic
    total_connections = len(df)
    protocol_counts = df["protocol"].value_counts()
    source_counts = df["source_ip"].value_counts()
    destination_counts = df["destination_ip"].value_counts()
    status_counts = df["connection_status"].value_counts()
    total_bytes = df["bytes"].sum()

    # Flag high connection counts for review
    suspicious_ips = source_counts[
        source_counts >= CONNECTION_THRESHOLD
    ]

    # Create output folder and charts
    CHART_DIR.mkdir(exist_ok=True)

    protocol_counts.plot(kind="bar", title="Connections by Protocol")
    plt.xlabel("Protocol")
    plt.ylabel("Number of Connections")
    plt.tight_layout()
    plt.savefig(CHART_DIR / "protocol_distribution.png")
    plt.close()

    source_counts.head(10).plot(
        kind="bar", title="Top Source IP Addresses"
    )
    plt.xlabel("Source IP")
    plt.ylabel("Number of Connections")
    plt.tight_layout()
    plt.savefig(CHART_DIR / "top_source_ips.png")
    plt.close()

    # Build text report
    lines = [
        "===== NETWORK THREAT LOG ANALYSIS =====",
        f"Records analyzed: {total_connections}",
        f"Total bytes recorded: {total_bytes:.0f}",
        "",
        "Connections by protocol:",
    ]

    for protocol, count in protocol_counts.items():
        lines.append(f"{protocol}: {count}")

    lines += ["", "Connections by source IP:"]

    for ip, count in source_counts.items():
        lines.append(f"{ip}: {count}")

    lines += ["", "Connections by destination IP:"]

    for ip, count in destination_counts.items():
        lines.append(f"{ip}: {count}")

    lines += ["", "Connection status counts:"]

    for status, count in status_counts.items():
        lines.append(f"{status}: {count}")

    lines += [
        "",
        f"Review threshold: {CONNECTION_THRESHOLD} connections per source IP",
        "Source IPs flagged for review:",
    ]

    if suspicious_ips.empty:
        lines.append("None")
    else:
        for ip, count in suspicious_ips.items():
            lines.append(f"REVIEW: {ip} had {count} connections")

    lines += [
        "",
        "Note: A high connection count is not proof of malicious activity.",
        "Investigate flagged records using additional evidence.",
    ]

    report = "\n".join(lines)
    REPORT_FILE.write_text(report, encoding="utf-8")

    print(report)
    print(f"\nReport saved to: {REPORT_FILE}")
    print(f"Charts saved in: {CHART_DIR}")


if __name__ == "__main__":
    main()
