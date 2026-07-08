import re
import sys

log_pattern = r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) \d+'

def parse_log_line(line):

    match = re.search(log_pattern , line)

    # analyze log:
    if match:
        return match.groupdict()
    else:
        return None


def procces_log_file(file_path):

    try:
        with open(file_path , "r") as file:
            for log in file:
                result = parse_log_line(log.strip())

                if result:
                    print(f"ip : {result["ip"]} time : {result["time"]} , method : {result["method"]} ,path : {result["path"]} , status : {result["status"]}")
                else:
                    print("Malformed line")
    except FileNotFoundError:
        print("file not founded!")



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"python analyzer.py <path_log_file>")
    else:
        log_file = sys.argv[1]
        procces_log_file(log_file)