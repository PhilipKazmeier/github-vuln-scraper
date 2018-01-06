#
# This file holds all configurations for the crawler and their corresponding regex patterns.
#

import re

# ----- SQL INJECTIONS ----- #

# https://regexr.com/3iifi
php_sql_config = {
    "name": "php-sqlinj",
    "description": "Searches for SQL injections in PHP code",
    # String tuples with a single element must always have a trailing comma or they are interpreted as single string
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
    # String tuples with a single element must always have a trailing comma or they are interpreted as single string
    "languages": ("php", "html"),
    "file_types": ("php", "html"),
    "regex": re.compile(
        b"(\"\s*(SELECT|INSERT|DELETE).*?\s(FROM|INTO)\s+?.*?(WHERE|VALUES)\s+.*?({?_(GET|POST|REQUEST)\[.*?\]))",
        re.IGNORECASE | re.MULTILINE)
}

# https://regexr.com/3iik2
node_sql_config = {
    "name": "node-sqlinj",
    "description": "Searches for SQL injections in NodeJS/Javascript code",
    # String tuples with a single element must always have a trailing comma or they are interpreted as single string
    "languages": ("js",),
    "file_types": ("js",),
    "regex": re.compile(
        b"([\"|\']\s*(SELECT|INSERT|DELETE).*?\s(FROM|INTO)\s+?.*?(WHERE|VALUES)\s.*?[\"|\']\s*\+\s*[a-zA-Z_0-9]+)",
        re.IGNORECASE | re.MULTILINE)
}

java_sql_config = {
    "name": "java-sqlinj",
    "description": "Searches for SQL injections in Java SQL Code",
    # String tuples with a single element must always have a trailing comma or they are interpreted as single string
    "languages": ("java",),
    "file_types": ("java",),
    "regex": re.compile(
        b"(\.executeQuery\(.*?\))",
        re.IGNORECASE | re.MULTILINE)
}

# ----- CROSS SITE SCRIPTING ----- #

# https://regexr.com/3iqr7
php_xss_config = {
    "name": "php-xss",
    "description": "Searches for XSS in PHP code",
    # String tuples with a single element must always have a trailing comma or they are interpreted as single string
    "languages": ("php",),
    "file_types": ("php", "html"),
    "regex": re.compile(b"(echo \$(_GET\[[\"\'][A-z0-9-_]*[\"\']\]))", re.IGNORECASE | re.MULTILINE)
}

# https://regexr.com/3irjj
js_xss_config = {
    "name": "js-xss",
    "description": "Searches for XSS in Javacript code",
    # String tuples with a single element must always have a trailing comma or they are interpreted as single string
    "languages": ("js",),
    "file_types": ("js", "html"),
    "regex": re.compile(b"(\.searchParams.get\(.*?\))|(\.split\(\"&\"\))", re.IGNORECASE | re.MULTILINE)
}

# ----- BUFFER OVERFLOW ----- #

# https://regexr.com/3ik3a
bo_cpp_config = {
    "name": "cpp-bo",
    "description": "Searches for Buffer Overflows in C and C++ code",
    # String tuples with a single element must always have a trailing comma or they are interpreted as single string
    "languages": ("c", "cpp"),
    "file_types": ("cpp", "c"),
    "regex": re.compile(
        b"(((strcpy|strcat|sprintf|vsprintf|scanf|printf)\(([A-Za-z0-9.,\-_>\s*&]+|(\"%[A-Za-z0-9]+\"))\))|(gets\([A-Za-z0-9\-_>.\s*&]+\)))",
        re.IGNORECASE | re.MULTILINE)
}

# https://regexr.com/3ingq
bo_cpp_strcpy_config = {
    "name": "cpp-bo-strcpy",
    "description": "Searches for Buffer Overflows in the usage of strcpy in C and C++ code",
    # String tuples with a single element must always have a trailing comma or they are interpreted as single string
    "languages": ("c", "cpp"),
    "file_types": ("cpp", "c"),
    "regex": re.compile(b"(char.*\[.*\];(.*[^{}]\s+\n)*?.*strcpy\(.*\))", re.IGNORECASE | re.MULTILINE)
}
