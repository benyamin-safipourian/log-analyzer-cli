import re
import sys
from collections import Counter
import time
import gzip
import argparse
import json

# log_pattern = r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) \d+'

# Compiled regex pattern for parsing
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) \d+'
)


# Parse a single log line and return extracted fields as a dictionary
# Returns None if the line does not match the expected log format
def parse_log_line(log):

    match = LOG_PATTERN.match(log)
    # analyze log:
    if match:
        return match.groupdict()
    else:
        return None


# Extract the hour part from a timestamp string
# Example input: "10/Oct/2000:13:55:36 -0700" -> returns "13"
# Returns None if the input is invalid or cannot be parsed
def extract_hour(time):
    try :
        hour = time.split(":")[1]
        return hour
    except (AttributeError , IndexError):
        return None


# Open a normal text log file or a gzipped log file
# Uses text mode with UTF-8 decoding
def open_log_file(file_path):
    if file_path.endswith('.gz'):
        return gzip.open(file_path, 'rt', encoding='utf-8')
    return open(file_path, 'r', encoding='utf-8')


# Process the log file and collect analysis results
def process_log_file(file_path, start_hour=None , end_hour=None):
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

            # Skip empty lines
            if not log:
                continue

            result = parse_log_line(log)

            if result:
                hour = extract_hour(result["time"])
                if start_hour is not None and end_hour is not None:
                    if hour is None:
                        continue

                    hour_int = int(hour)
                    if not (start_hour <= hour_int <= end_hour):
                        continue

                endpoint_counts[result["path"]] += 1
                unique_ips.add(result["ip"])
                total_requests += 1

                status_code = int(result["status"])
                if 400 <= status_code < 600:
                    error_count += 1

                # Detect suspicious login failures:
                # POST requests to a login-related path that returned 401
                if (
                    status_code == 401
                    and "login" in result["path"].lower()
                    and result["method"] == "POST"
                ):
                    suspicious_login_failures[result["ip"]] += 1

                # Extract hour from the timestamp and count requests by hour
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



# Print a human-readable analysis report
# top_n controls how many of the most common endpoints are shown
def print_report(report , top_n ):

    # Show the top N endpoints
    print(f"\nTop {top_n} Endpoints:")
    if report["endpoint_counts"]:
        for path, count in report["endpoint_counts"].most_common(top_n):
            print(f"- {path}: {count}")
    else:
        print("No endpoints found.")

    # Print basic summary metrics
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

    # Threshold for flagging suspicious failed login attempts
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

    # Find the highest request count for scaling the histogram
    # Maximum width of the histogram bar
    max_count = max(hours.values())
    max_bar_width = 32

    # Print histogram header
    print(f"\nHours present in log: {start_hour:02d} to {end_hour:02d}")
    print("Time distribution (scaled):")
    print("Hour Range  |            Histogram             |    Count |   Peak")
    print("-" * 75)

    for hour in range(start_hour, end_hour + 1):
        hour_str = f"{hour:02d}"
        count = hours.get(hour_str, 0)
        next_hour = (hour + 1) % 24

        # Scale bar length relative to the peak hour
        if max_count > 0:
            bar_length = int((count / max_count) * max_bar_width)
        else:
            bar_length = 0

        # Ensure non-zero counts still show at least one block
        if count > 0 and bar_length == 0:
            bar_length = 1

        bar = "■" * bar_length

        # Calculate percentage relative to the peak hour
        percent = (count / max_count) * 100 if max_count > 0 else 0

        print(
            f"{hour_str}:00-{next_hour:02d}:00 | "
            f"{bar:<32} | "
            f"{count:>8} | "
            f"{percent:>6.1f}%"
        )
        

def print_json_report(report , top_n):


    if report["total_requests"] > 0:
        error_rate = (report["error_count"] / report["total_requests"]) * 100
    else:
        error_rate = 0

    threshold = 20
    suspicious_ips = [
        {"ip": ip ,  "count" : count}
        for ip, count in sorted(report["suspicious_login_failures"].items() , key=lambda item : item[1], reverse=True)
        if count >= threshold
    ]

    json_data = {
        "summary" : {
            "total_requests" : report["total_requests"],
            "Unique_IPs" : len(report["unique_ips"]),
            "Malformed_logs" : report["malformed_logs"],
            "error_count" : report["error_count"],
            "error_rate" : round(error_rate, 2)
        },
        "top_endpoints" : [
            {"path" : path , "count" : count}
            for path , count in report["endpoint_counts"].most_common(top_n)
        ],
        "suspicion_activity" : {
            "threshold" : threshold,
            "ips" : suspicious_ips
        }
    }
    print(json.dumps(json_data, indent=2, ensure_ascii=False))


# Parse command-line arguments:
def parse_args():

    parser = argparse.ArgumentParser()
    parser.add_argument("log_file")
    parser.add_argument("--top" , type=int, default=10)
    parser.add_argument("--start-hour" , type=int)
    parser.add_argument("--end-hour" , type=int)
    parser.add_argument("--json" , action="store_true")

    return parser.parse_args()



def main():

    # Parse CLI arguments
    args = parse_args()

    if args.top <= 0:
        print("Error: --top must be greater than 0")
        sys.exit(1)

    if args.start_hour is not None and not ( 0 <= args.start_hour <= 23):
        print("Error: --start-hour must be between 0 and 23")
        sys.exit(1)

    if args.end_hour is not None and not (0 <= args.end_hour <= 23):
        print("Error: --end-hour must be between 0 and 23")
        sys.exit(1)

    if (args.start_hour is None) != (args.end_hour is None):
        print("Error: both --start-hour and --end-hour must be provided together")
        sys.exit(1)


    try:
        start_time = time.perf_counter()
        report = process_log_file(args.log_file, start_hour=args.start_hour, end_hour=args.end_hour)

        if args.json:
            print_json_report(report , args.top)
        else:

            print_report(report , args.top)

            end_time = time.perf_counter()
            total_time = end_time - start_time
            print(f"\nExecution time: {total_time:.4f} seconds")


    except FileNotFoundError:
        print(f"Error: file not found: {args.log_file}")
        sys.exit(1)

    except gzip.BadGzipFile:
        print(f"Error: invalid or corrupted gzip file: {args.log_file}")
        sys.exit(1)

    # Handle UTF-8 decoding errors
    except UnicodeDecodeError:
        print(f"Error: could not decode file as UTF-8: {args.log_file}")
        sys.exit(1)

    # Handle other OS/file access related errors
    except OSError as e:
        print(f"Error: failed to read file '{args.log_file}': {e}")
        sys.exit(1)





if __name__ == "__main__":
    main()

