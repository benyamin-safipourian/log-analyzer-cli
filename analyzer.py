import re
import sys
from collections import Counter

# log_pattern = r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) \d+'

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) \d+'
)

def parse_log_line(log):

    match = LOG_PATTERN.match(log)
    # analyze log:
    if match:
        return match.groupdict()
    else:
        return None

def extract_hour(time):
    try :
        hour = time.split(":")[1]
        return hour
    except (AttributeError , IndexError):
        return None


def process_log_file(file_path):
    unique_ips = set()
    endpoint_counts = Counter()
    hour_counts = Counter()
    error_count = 0
    total_requests = 0
    malformed_logs = 0

    try:
        with open(file_path , "r") as file:
            for log in file:

                log = log.strip()
                if not log:
                    continue

                result = parse_log_line(log)

                if result:

                    endpoint_counts[result["path"]] += 1
                    unique_ips.add(result["ip"])
                    total_requests += 1

                    status_code = int(result["status"])
                    if 400 <= status_code < 600:
                        error_count += 1

                    hour = extract_hour(result["time"])
                    if hour is not None:
                        hour_counts[hour] += 1

                else:
                    malformed_logs += 1
        
        return {
            "total_requests": total_requests,
            "malformed_logs": malformed_logs,
            "unique_ips": unique_ips,
            "endpoint_counts": endpoint_counts,
            "error_count": error_count,
            "hour_counts" : dict(sorted(hour_counts.items()))
        }



    except FileNotFoundError:
        print("file not founded!")




def print_report(report):
    print("\nTop 10 Endpoints:")
    if report["endpoint_counts"]:
        for path, count in report["endpoint_counts"].most_common(10):
            print(f"- {path}: {count}")
    else:
        print("No endpoints found.")

    print("-" * 40)
    print(f"total requests : {report['total_requests']}")
    print(f"malformed logs : {report['malformed_logs']}")
    print(f"Unique IPs: {len(report['unique_ips'])}")
    print("-" * 40)


    # handling zero division error:
    if report["total_requests"] > 0:
        error_rate = (report["error_count"] / report["total_requests"]) * 100
    else:
        error_rate = 0

    print(f"Error rate : {error_rate:.2f}%")

    print("-" * 40)

    hours = report["hour_counts"]
    
    if not hours:
        print("Time distribution: no valid hours found.")
        return

    start_hour = min(int(hour) for hour in hours)
    end_hour = max(int(hour) for hour in hours)
    max_count = max(hours.values())
    max_bar_width = 32

    print(f"Hours present in log: {start_hour:02d} to {end_hour:02d}")
    print("Time distribution (scaled):")
    print("Hour Range  |            Histogram             |    Count |   Peak")
    print("-" * 75)

    for hour in range(start_hour, end_hour + 1):
        hour_str = f"{hour:02d}"
        count = hours.get(hour_str, 0)
        next_hour = (hour + 1) % 24

        if max_count > 0:
            bar_length = int((count / max_count) * max_bar_width)
        else:
            bar_length = 0

        if count > 0 and bar_length == 0:
            bar_length = 1

        bar = "■" * bar_length
        percent = (count / max_count) * 100 if max_count > 0 else 0

        print(
            f"{hour_str}:00-{next_hour:02d}:00 | "
            f"{bar:<32} | "
            f"{count:>8} | "
            f"{percent:>6.1f}%"
        )
        


def main():
    if len(sys.argv) < 2:
        print(f"python analyzer.py <path_log_file>")
    else:
        log_file = sys.argv[1]
        report = process_log_file(log_file)
        print_report(report)



if __name__ == "__main__":
    main()

