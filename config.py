import re

access_token = "***REMOVED***"

worker_count = 8


# Search all repositories with:
# - 75 to 150 stars
# - updated in the last 12 months
# - smaller than 10 MB TODO remove?
github_repo_query = 'stars:75..150 pushed:>2017-01-08 size:<=10000'

progress_file = "processed_repos.txt"

file_types = {
    "sql_injection":    ("php"),
    "xss":              ("php"),
    "buffer_overflow":  ("c", "cpp")
}

__sql_query = re.compile(b"(.*(SELECT|INSERT).* \$_GET\[.*\])", re.DOTALL | re.IGNORECASE | re.MULTILINE)
__xss_query = re.compile(b"(.*\$_GET\[.*\])", re.DOTALL | re.IGNORECASE | re.MULTILINE)
__bo_query = re.compile(b"(.*(strcpy).*)", re.DOTALL | re.IGNORECASE | re.MULTILINE)

regex_queries = {
    "sql_injection":    __sql_query,
    "xss":              __xss_query,
    "buffer_overflow":  __bo_query
}