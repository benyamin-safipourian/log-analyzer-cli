import re
import sys
from collections import Counter

log_pattern = r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) \d+'

def parse_log_line(line):

    match = re.search(log_pattern , line)

    # analyze log:
    if match:
        return match.groupdict()
    else:
        return None


unique_ips = set()
endpoint_counts = Counter()
def procces_log_file(file_path):
    total_requests = 0
    malformed_logs = 0

    try:
        with open(file_path , "r") as file:
            for log in file:
                result = parse_log_line(log.strip())

                if result:
                    endpoint_counts[result["path"]] += 1
                    unique_ips.add(result["ip"])
                    total_requests += 1
                else:
                    malformed_logs += 1

        print("\nTop 10 Endpoints:")
        if endpoint_counts:
            for path, count in endpoint_counts.most_common(10):
                print(f"- {path}: {count}")
        else:
            print("No endpoints found.")

        print("-" * 40)
        print(f"total requests : {total_requests}")
        print(f"malformed logs : {malformed_logs}")
        print(f"Unique IPs: {len(unique_ips)}")
        print("-" * 40)

    except FileNotFoundError:
        print("file not founded!")



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"python analyzer.py <path_log_file>")
    else:
        log_file = sys.argv[1]
        procces_log_file(log_file)