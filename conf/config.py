#
# This file holds all configurations for the crawler.
#

from types import SimpleNamespace
from conf import patterns

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
tmp_base_dir = "tmp"

configs = {c["name"]: SimpleNamespace(**c) for c in (
    patterns.php_sql_config,
    patterns.php_simple_sql_config,
    patterns.node_sql_config,
    patterns.java_sql_config,
    patterns.php_xss_config,
    patterns.bo_cpp_config
)}
