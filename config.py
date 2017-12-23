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
    "description": "Searches for SQL injections in PHP code",
    "languages": ("php", "html"),
    "file_types": ("php", "html"),
    "regex": re.compile(b"(\"\s*(SELECT|INSERT|DELETE).*?\s+(WHERE|INTO)\s+{?\$[a-zA-Z_0-9]+}?.*?\")",
                        re.IGNORECASE | re.MULTILINE),
    "processed": "php-sqlinj.txt",
    "log": "php-sqlinj.log"
}

bo_cpp_config = {
    "name": "cpp-bo",
    "description": "Searches for Buffer Overflows in C and C++ code",
    "languages": ("c", "cpp"),
    "file_types": ("cpp", "c"),
    "regex": re.compile(b"((printf|strcpy|strcmp)\(.*,\s*.*\))", re.IGNORECASE | re.MULTILINE),
    "processed": "cpp-bo.txt",
    "log": "cpp-bo.log"
}

configs = {c["name"]: SimpleNamespace(**c) for c in (
    sql_config,
    bo_cpp_config
)}
