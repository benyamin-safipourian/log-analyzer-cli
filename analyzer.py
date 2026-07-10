import re
import sys
from collections import Counter
import time
import gzip

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

def open_log_file(file_path):
    if file_path.endswith('.gz'):
        return gzip.open(file_path, 'rt', encoding='utf-8')
    return open(file_path, 'r', encoding='utf-8')


def process_log_file(file_path):
    unique_ips = set()
    endpoint_counts = Counter()
    hour_counts = Counter()
    suspicious_login_failures = Counter()
    error_count = 0
    total_requests = 0
    malformed_logs = 0

    with open_log_file(file_path) as file:
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

                if (
                    status_code == 401
                    and "login" in result["path"].lower()
                    and result["method"] == "POST"
                ):
                    suspicious_login_failures[result["ip"]] += 1

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
        "hour_counts": dict(sorted(hour_counts.items())),
        "suspicious_login_failures": suspicious_login_failures,
    }


def print_report(report):
    print("\nTop 10 Endpoints:")
    if report["endpoint_counts"]:
        for path, count in report["endpoint_counts"].most_common(10):
            print(f"- {path}: {count}")
    else:
        print("No endpoints found.")

    print("-" * 40)
    print("\n")
    print(f"total requests : {report['total_requests']}")
    print(f"malformed logs : {report['malformed_logs']}")
    print(f"Unique IPs: {len(report['unique_ips'])}")
    print("\n")
    print("-" * 40)


    # handling zero division error:
    if report["total_requests"] > 0:
        error_rate = (report["error_count"] / report["total_requests"]) * 100
    else:
        error_rate = 0

    print(f"\nError rate : {error_rate:.2f}%\n")

    print("-" * 40)


    print("\nSuspicious login activity:")

    threshold = 20
    suspicious_ips = {
        ip: count
        for ip, count in report["suspicious_login_failures"].items()
        if count >= threshold
    }

    if suspicious_ips:
        for ip, count in sorted(suspicious_ips.items(), key=lambda item: item[1], reverse=True):
            print(f"- {ip}: {count} failed login attempts (POST /login + 401)")
    else:
        print(f"No suspicious login activity found. Threshold: {threshold}\n")


    print("-" * 40)

    hours = report["hour_counts"]

    if not hours:
        print("Time distribution: no valid hours found.")
        return

    start_hour = min(int(hour) for hour in hours)
    end_hour = max(int(hour) for hour in hours)
    max_count = max(hours.values())
    max_bar_width = 32

    print(f"\nHours present in log: {start_hour:02d} to {end_hour:02d}")
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
        sys.exit(1)
    else:
        log_file = sys.argv[1]
        try:
            start_time = time.perf_counter()

            report = process_log_file(log_file)
            print_report(report)

            end_time = time.perf_counter()
            total_time = end_time - start_time
            print(f"\nExecution time: {total_time:.4f} seconds")


        except FileNotFoundError:
            print(f"Error: file not found: {log_file}")
            sys.exit(1)

        except gzip.BadGzipFile:
            print(f"Error: invalid or corrupted gzip file: {log_file}")
            sys.exit(1)

        except UnicodeDecodeError:
            print(f"Error: could not decode file as UTF-8: {log_file}")
            sys.exit(1)

        except OSError as e:
            print(f"Error: failed to read file '{log_file}': {e}")
            sys.exit(1)





if __name__ == "__main__":
    main()

