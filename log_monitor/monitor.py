
import re
from collections import Counter

LOG_FILE = "sample_logs/ssh_test.log"
THRESHOLD = 5


def analyze_logs(log_file):
    failed_attempts = Counter()

    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            if "Failed password" in line:
                match = re.search(
                    r"from (\d{1,3}(?:\.\d{1,3}){3})",
                    line
                )
                if match:
                    failed_attempts[match.group(1)] += 1

    return failed_attempts


def monitor_logs():
    try:
        failed_attempts = analyze_logs(LOG_FILE)

        print("\n=== SSH Security Log Monitor ===")

        if not failed_attempts:
            print("No failed SSH login attempts found.")
            return

        for ip, count in failed_attempts.items():
            print(f"IP Address: {ip}")
            print(f"Failed Attempts: {count}")

            if count >= THRESHOLD:
                print("[ALERT] Suspicious login activity!")
            else:
                print("[INFO] Below alert threshold.")

            print("----------------------------")

    except FileNotFoundError:
        print("Error: Log file not found.")


if __name__ == "__main__":
    monitor_logs()
               
