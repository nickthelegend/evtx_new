import subprocess
import os
from datetime import datetime, timedelta

def export_logs(logs, output_dir):
    """
    Export full event logs using 'wevtutil epl'.
    """
    for log in logs:
        output_file = os.path.join(output_dir, f"{log}.evtx")
        print(f"Exporting log: {log} to {output_file}")

        try:
            result = subprocess.run(
                ["wevtutil", "epl", log, output_file, "/ow:true"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print(f"Successfully exported: {log}")
            else:
                print(f"Failed to export: {log}. Error: {result.stderr}")
        except Exception as e:
            print(f"Error exporting log {log}: {e}")


def process_recent_logs(logs, output_dir):
    """
    Query recent logs using 'wevtutil qe'.
    """
    now = datetime.now()
    ten_minutes_ago = now - timedelta(minutes=10)
    time_filter = ten_minutes_ago.strftime("%Y-%m-%dT%H:%M:%S")

    for log in logs:
        output_file = os.path.join(output_dir, f"recent_{log}.evtx")
        print(f"Querying recent events for log: {log}")

        try:
            # Use 'wevtutil qe' to query logs based on time filter
            query = f"*[System[TimeCreated[@SystemTime >= '{time_filter}']]]"
            result = subprocess.run(
                ["wevtutil", "qe", log, "/q", query, "/f:RenderedXml"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Save the queried logs to a file
                with open(output_file, "w", encoding="utf-8") as file:
                    file.write(result.stdout)
                print(f"Successfully queried recent events for: {log}")
            else:
                print(f"Failed to query recent events for {log}. Error: {result.stderr}")
        except Exception as e:
            print(f"Error querying recent logs for {log}: {e}")


def main():
    # Define the logs to process and directories
    logs = ["Application", "Security", "System"]
    output_dir = "C:/RecentLogs"

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Export full logs
    export_logs(logs, output_dir)

    # Process recent logs
    process_recent_logs(logs, output_dir)


if __name__ == "__main__":
    main()
