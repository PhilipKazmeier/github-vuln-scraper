#
# Crawler for vulnerabilities on GitHub
#


# IMPORTS
import os
import re
import mmap
from concurrent.futures import ThreadPoolExecutor

from git import Git
from github import Github
from shutil import rmtree

import config


def check_data(data, pattern):
    # Checks if the given data contains a match for the given query
    matches = pattern.findall(data)
    for match in matches:
        print(match)


def check_file(file):
    # Check if the given file contains any matches for one of our vulnerabilities
    with open(file=file, mode="r", encoding="UTF-8") as f:
        data = mmap.mmap(fileno=f.fileno(), length=0, prot=mmap.PROT_READ)
        if file.endswith(config.file_types["sql_injection"]):
            check_data(data, config.regex_queries["sql_injection"])
        if file.endswith(config.file_types["xss"]):
            check_data(data, config.regex_queries["xss"])
        if file.endswith(config.file_types["buffer_overflow"]):
            check_data(data, config.regex_queries["buffer_overflow"])

def check_folder(folder):
    # Check if the given folder contains any files with matches for one of our vunerabilities
    for dname, dirs, files in os.walk(folder):
        for fname in files:
            fpath = os.path.join(dname, fname)
            if os.stat(fpath).st_size == 0:    # Empty file
                continue
            check_file(fpath)

def check_repo(repo):
    try:
        print("Searching in %s" % repo.full_name)
        if not os.path.exists("tmp/%s" % repo.full_name):
            os.makedirs("tmp/%s" % repo.full_name)
        Git("tmp/%s" % repo.full_name).clone(repo.clone_url, "--depth", "1")
        check_folder("tmp/%s" % repo.full_name)
        rmtree("tmp/%s" % repo.full_name)
        print("Finished %s" % repo.full_name)
    except Exception as e:
        print(e)



# VARIABLES
g = Github(login_or_token=config.access_token)
repos = g.search_repositories(query=config.github_repo_query, sort='stars', order='desc')
i = 0
with ThreadPoolExecutor(max_workers=config.worker_count) as executer, open(config.progress_file, "r+") as file:
    lines = tuple(file)
    lines = map(lambda s: s.strip(), lines) # Remove newline characters
    for repo in repos:
        if not repo.full_name in lines:  # TODO fix
            file.write(repo.full_name + "\n")
            executer.submit(check_repo, repo)
            i = i + 1
            if i == 1:
                break
