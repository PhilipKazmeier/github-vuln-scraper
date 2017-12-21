import re
from types import SimpleNamespace

worker_count = 1
access_token = "***REMOVED***"

# Search parameters
# github_repo_query = 'stars:75..150 pushed:>2017-01-08 size:<=10000'
search_params = {
    "stars": (75, 150),
    "last_accessed": "2017-01-08",
    "max_size": 10000,
}

progress_file = "processed_repos.txt"

sql_config = {
    "name": "php-sqlinj",
    "language": "php",
    "filetypes": ("php"),
    "regex": re.compile(b"(\"\s*(SELECT|INSERT|DELETE)\s.*?{?\$[a-zA-Z_0-9]+}?.*?\")", re.IGNORECASE | re.MULTILINE),
}

configs = {c["name"]: SimpleNamespace(**c) for c in (
    sql_config,
)}
