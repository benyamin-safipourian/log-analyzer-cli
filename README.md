# log-analyzer-cli

A Python CLI tool for analyzing web server access logs (Apache/Nginx-style combined log format). It parses log files (plain text or gzip-compressed), extracts useful statistics, detects suspicious login activity, and generates human-readable or JSON reports.

## Features

- **Log parsing** — Parses standard access log lines using regex:
IP - - [time] “METHOD PATH PROTOCOL” STATUS SIZE
- **Gzip support** — Automatically detects and reads `.gz` compressed log files.
- **Traffic statistics**
  - Total requests
  - Malformed (unparsable) log lines
  - Unique IP addresses
  - Top N most requested endpoints
  - Overall error rate (4xx/5xx status codes)
- **Suspicious login detection** — Flags IPs with repeated failed login attempts (`POST` requests to a login-related path returning HTTP `401`), based on a configurable threshold.
- **Hourly traffic distribution** — Text-based histogram showing request volume per hour.
- **Time range filtering** — Restrict analysis to a specific hour range (`--start-hour` / `--end-hour`).
- **Output formats** — Human-readable console report or structured JSON output.



## Requirements

- Python 3.7+
- No external dependencies (uses only the standard library)



## Installation

No installation needed — just download the script.

```bash


## Usage

python log_analyzer.py <log_file> [options]

### Arguments

| Argument         | Type   | Default | Description                                                   |
|------------------|--------|---------|-----------------------------------------------------------------|
| `log_file`       | string | -       | Path to the log file (`.log`, `.txt`, or `.gz`)                 |
| `--top`          | int    | 10      | Number of top endpoints to display                              |
| `--start-hour`   | int    | None    | Start hour for filtering (0–23), must be used with `--end-hour` |
| `--end-hour`     | int    | None    | End hour for filtering (0–23), must be used with `--start-hour` |
| `--json`         | flag   | False   | Output the report as JSON instead of plain text                 |

### Examples

**Basic report:**

python log_analyzer.py access.log

**Show top 5 endpoints:**

python log_analyzer.py access.log --top 5

**Analyze traffic between 08:00 and 18:00:**

python log_analyzer.py access.log --start-hour 8 --end-hour 18

**Analyze a gzip-compressed log file:**

python log_analyzer.py access.log.gz

**Get JSON output:**

python log_analyzer.py access.log --json

## Sample Output (Text Report)


Top 10 Endpoints:
- /index.html: 1500
- /login: 800
- /api/data: 650

----------------------------------------

total requests : 5000
malformed logs : 12
Unique IPs: 320

----------------------------------------

Error rate : 4.32%

----------------------------------------

Suspicious login activity:
- 192.168.1.10: 45 failed login attempts (POST /login + 401)

----------------------------------------

Hours present in log: 00 to 23
Time distribution (scaled):
Hour Range  |            Histogram             |    Count |   Peak
---------------------------------------------------------------------
00:00-01:00 | ■■■■                             |      120 |   25.0%
...

Execution time: 0.1234 seconds

## Sample Output (JSON Report)

json
{
  "summary": {
"total_requests": 5000,
"Unique_IPs": 320,
"Malformed_logs": 12,
"error_count": 216,
"error_rate": 4.32
  },
  "top_endpoints": [
{ "path": "/index.html", "count": 1500 },
{ "path": "/login", "count": 800 }
  ],
  "suspicion_activity": {
"threshold": 20,
"ips": [
{ "ip": "192.168.1.10", "count": 45 }
]
  }
}

```



## Design Decisions



### **Why re.compile instead of re.search?**

- **What:** Regex matching strategy for log line parsing.
- **Choice:** Used `re.compile()` once at module level to create a compiled pattern, then reused `.match()` on it for every line — instead of calling `re.search()` (uncompiled) repeatedly.
- **Why:** `re.compile` parses and optimizes the pattern once; every subsequent match reuses that compiled object, avoiding re-parsing overhead on every line. For large log files with thousands/millions of lines, this gives a real speed improvement. It also allows the pattern to be reused across functions cleanly.



### **Why POST (not GET) for suspicious login detection?**

- **What:** Method filter in brute-force detection logic.
- **Choice:** Flag failed attempts on `POST /login` with status `401`, not `GET /login`.
- **Why:** Login *submissions* (credential checks) happen via `POST`—that's where failed authentication attempts actually occur. `GET /login` typically just loads the login page and doesn't represent an attack attempt. Filtering on `POST` avoids false positives from legitimate users repeatedly visiting the login page.



### **Why collections.Counter for aggregation?**

- **What:** Counting IPs, endpoints, and hourly traffic.
- **Choice:** Used `Counter` instead of manual dictionary loops.
- **Why:** Built-in, optimized in C, and expressive. `.most_common(n)` gives top-N results in one call without manual sorting. Less code, fewer bugs, and better performance than manually incrementing dict values.



## Challenges

The main challenge was **automatic 5XX error-spike detection** — identifying 
time windows where server errors suddenly increase. I researched the 
statistical logic (moving averages, variance-based thresholds to separate 
real incidents from noise) and understood the approach, but implementing it 
turned out to be more complex and time-consuming than expected, so I decided 
to skip it for this version. The rest of the tool was straightforward, with 
Python's standard library (`re`, `collections.Counter`, `gzip`, `argparse`) 
providing everything needed.

## Log Format Expected

The parser expects the standard **NCSA Combined/Common Log Format**:

127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326

Lines that don't match this format are counted as **malformed logs** and skipped from statistics.

## Suspicious Login Detection Logic

An IP is flagged if it has **20 or more** failed login attempts matching:

- HTTP method: `POST`
- Path contains: `login` 
- Status code: `401`

The threshold can be adjusted by editing the `threshold` variable in `print_report()` and `print_json_report()`.

## Error Handling

The tool gracefully handles:

- Missing files (`FileNotFoundError`)
- Corrupted gzip files (`gzip.BadGzipFile`)
- Encoding issues (`UnicodeDecodeError`)
- General I/O errors (`OSError`)
- Invalid CLI argument values (e.g., `--top <= 0`, invalid hour ranges)

