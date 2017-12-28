import re
from types import SimpleNamespace

worker_count = 8
access_token = "***REMOVED***"

# Search parameters for the GitHub API
# github_repo_query = 'stars:75..150 pushed:>2017-01-08 size:<=10000'
search_params = {
    "stars": (75, 150),
    "last_accessed": "2017-01-08",
    "max_size": 10000,
}

processed_base_dir = "processed"
logs_base_dir = "logs"

# https://regexr.com/3iifi
php_sql_config = {
    "name": "php-sqlinj",
    "description": "Searches for SQL injections in PHP code",
    "languages": ("php", "html"),
    "file_types": ("php", "html"),
    "regex": re.compile(
        b"(\"\s*(SELECT|INSERT|DELETE).*?\s(FROM|INTO)\s+?.*?(WHERE|VALUES)\s+.*?({?\$[a-zA-Z_0-9]+}?).*?\")",
        re.IGNORECASE | re.MULTILINE)
}

# https://regexr.com/3iig7
php_simple_sql_config = {
    "name": "php-simp-sqlinj",
    "description": "Searches for SQL injections in PHP code with _GET or _POST or _REQUEST",
    "languages": ("php", "html"),
    "file_types": ("php", "html"),
    "regex": re.compile(b"(\"\s*(SELECT|INSERT|DELETE).*?\s(WHERE|INTO)\s+.*{?\$[a-zA-Z_0-9]+}?.*?\")",
                        re.IGNORECASE | re.MULTILINE)
}

# https://regexr.com/3ie5u
php_xss_config = {
    "name": "php-xss",
    "description": "Searches for XSS in PHP code",
    "languages": ("php"),
    "file_types": ("php", "html"),
    "regex": re.compile(b"(echo \$_GET\[[\"\'][A-z0-9-_]*[\"\']\])", re.IGNORECASE | re.MULTILINE)
}

# https://regexr.com/3ie6d
bo_cpp_config = {
    "name": "cpp-bo",
    "description": "Searches for Buffer Overflows in C and C++ code",
    "languages": ("c", "cpp"),
    "file_types": ("cpp", "c"),
    "regex": re.compile(b"((printf|strcpy|strcmp)\(.*,\s*.*\))", re.IGNORECASE | re.MULTILINE)
}

configs = {c["name"]: SimpleNamespace(**c) for c in (
    php_sql_config,
    php_simple_sql_config,
    php_xss_config,
    bo_cpp_config
)}
