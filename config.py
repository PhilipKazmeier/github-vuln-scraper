import re
from types import SimpleNamespace

worker_count = 8
access_token = "***REMOVED***"

# Search parameters
# github_repo_query = 'stars:75..150 pushed:>2017-01-08 size:<=10000'
search_params = {
    "stars": (75, 150),
    "last_accessed": "2017-01-08",
    "max_size": 10000,
}


processed_base_dir = "processed"
logs_base_dir = "logs"

sql_config = {
    "name": "php-sqlinj",
    "language": "php",
    "filetypes": ("php", "html"),
    "regex": re.compile(b"(\"\s*(SELECT|INSERT|DELETE).*?\s+(FROM|INTO)\s+{?\$[a-zA-Z_0-9]+}?.*?\")", re.IGNORECASE | re.MULTILINE),
    "processed": "php-sqlinj.txt",
    "log": "php-sqlinj.log"
}

bo_cpp_config = {
    "name": "cpp-bo",
    "language": "cpp",  # TODO multiple languages
    "filetypes": ("cpp", "c"),
    "regex": re.compile(b"((printf|strcpy|strcmp)\(.*,\s*.*\))", re.IGNORECASE | re.MULTILINE),
    "processed": "cpp-bo.txt",
    "log": "cpp-bo.log"
}

configs = {c["name"]: SimpleNamespace(**c) for c in (
    sql_config,
)}
