import re

log_pattern = r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) \d+'

def parse_log_line(line):

    match = re.search(log_pattern , line)

    # analyze log:
    if match:
        return match.groupdict()
    else:
        return None


if __name__ == "__main__":
    test_line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products/1877 HTTP/1.1" 200 5324 "-" "Mozilla/5.0 ..."'
    result = parse_log_line(test_line)

    if result:
        print(f"IP: {result['ip']}")
        print(f"Path: {result['path']}")
        print(f"Status: {result['status']}")
    else:
        print("*-*")