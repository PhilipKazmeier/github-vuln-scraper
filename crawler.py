#
# Crawler for vulnerabilities on GitHub
#


# IMPORTS
import os
import sys
import time
import mmap
from concurrent.futures import ThreadPoolExecutor

from git import Git
from github import Github
from shutil import rmtree

import config


def check_data(data, pattern):
    # Checks if the given data contains a match for the given query
    matches = pattern.findall(data)

    # As result set we return the content of the first group for each matched regular expression
    result = []
    for match in matches:
        if match is str:
            result.append(match)
        else:
            result.append(match[0])
    return result

def check_file(file, search_pattern):
    # Check if the given file contains any matches for one of our vulnerabilities
    with open(file=file, mode="r", encoding="UTF-8") as f:
        map = mmap.mmap(fileno=f.fileno(), length=0, prot=mmap.PROT_READ)
        return check_data(map, search_pattern)

def search_folder(folder, filetypes, search_pattern):
    # Check if the given folder contains any files with matches for one of our vunerabilities
    results = []
    for dname, _, files in os.walk(folder):
        for fname in files:
            fpath = os.path.join(dname, fname)
            if os.stat(fpath).st_size > 0 and has_filetype(fpath, filetypes):
                matches = check_file(fpath, search_pattern)

                # Only append files which actually have any matches
                if len(matches) > 0:
                    results.append((fname, matches))
    return results

def has_filetype(fname, filetypes):
    for ftype in filetypes:
        if fname.endswith(ftype):
            return True
    return False

def check_repository(repo, search_conf):
    try:
        path = clone_repository("tmp", repo)
        check_folder(path, search_conf)
        rmtree(path)

    except Exception as e:
        print("Exception occurred while searching: %s" % e)

def check_folder(path, search_conf):
    print("Searching in %s" % path)
    results = search_folder(path, search_conf.filetypes, search_conf.regex)

    if len(results) > 0:
        for fpath, matches in results:
            print("Possibly vulnerable file: %s" % fpath)
            for match in matches:
                print("\t%s" % match)

    print("Finished %s" % path)

def clone_repository(rootdir, repo):
    repo_path = "%s/%s" % (rootdir, repo.full_name)
    if not os.path.exists(repo_path):
        os.makedirs(repo_path)
    Git(repo_path).clone(repo.clone_url, "--depth", "1")
    return repo_path

def build_query(stars, last_accessed, max_size, language):
    query = "stars:%i..%i pushed:>%s size:<%i language:%s" % (
        stars[0], stars[1], last_accessed, max_size, language
    )
    return query

def execute_search(repos, search_conf, workers):
    fn = lambda repo: check_repository(repo, search_conf)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(fn, repos)
        for result in results:
            print(result)

if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("Please specify a search config name")
        sys.exit(1)

    search_conf = config.configs[sys.argv[1]]
    print("Using configuration: %s" % search_conf.name)

    ghub = Github(login_or_token=config.access_token)
    query = build_query(language=search_conf.language, **config.search_params)
    repos = ghub.search_repositories(query=query, sort='stars', order='desc')

    execute_search(repos, search_conf, config.worker_count)
