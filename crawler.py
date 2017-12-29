#
# Crawler for vulnerabilities on GitHub
#


# IMPORTS
import os
import sys
import mmap
from queue import Queue
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from git import Git
from github import Github
from shutil import rmtree

from conf import config
from lib.RepoSearcher import RepoSearcher


def check_contents(data, pattern):
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
        fmap = mmap.mmap(fileno=f.fileno(), length=0, prot=mmap.PROT_READ)
        return check_contents(fmap, search_pattern)


def check_folder(folder, file_types, search_pattern):
    # Check if the given folder contains any files with matches for one of our vunerabilities
    results = []
    for dname, _, files in os.walk(folder):
        # skip all paths that contain test, to avoid false positives
        if "test" in dname:
            continue
        for fname in files:
            fpath = os.path.join(dname, fname)
            if os.path.exists(fpath) and os.stat(fpath).st_size > 0 and fname.endswith(file_types):
                matches = check_file(fpath, search_pattern)

                # Only append files which actually have any matches
                if len(matches) > 0:
                    results.append((dname[len(folder) + 1:], fname, matches))
    return results


def clone_repository(root_dir, repo):
    # Clones the given repo in a folder in the given directory
    clone_path = "%s/%s" % (root_dir, repo.owner.login)
    if not os.path.exists(clone_path):
        os.makedirs(clone_path, exist_ok=True)
    Git(clone_path).clone(repo.clone_url, "--depth", "1")
    return "%s/%s" % (root_dir, repo.full_name)


def check_repository(repo, search_conf):
    # Checks the repository with the given search configuration
    try:
        path = clone_repository("tmp", repo)
        results = check_folder(path, search_conf.file_types, search_conf.regex)
        rmtree(path)

        return repo, results
    except Exception as e:
        print("Exception occurred while searching: %s" % e)
        traceback.print_exc(file=sys.stderr)
        return repo, []


def worker_fn(result_queue, searcher, search_conf):
    while True:
        try:
            repo = searcher.get_next()
            if repo is None:
                break
            result = check_repository(repo, search_conf)
            result_queue.put(result)
        except BaseException as e:
            print(e)
            raise e


def write_to_file(output_file, data):
    # write the given data to the given file
    output_file.write(data + "\n")
    output_file.flush()


def execute_search(search_conf, searcher, workers):
    if not os.path.exists(config.logs_base_dir):
        os.makedirs(config.logs_base_dir)
    if not os.path.exists(config.processed_base_dir):
        os.makedirs(config.processed_base_dir)
    log_file = "%s/%s.log" % (config.logs_base_dir, search_conf.name)
    cache_file = "%s/%s.txt" % (config.processed_base_dir, search_conf.name)

    with ThreadPoolExecutor(max_workers=workers) as executor, open(cache_file, "a+") as processed_repos_file, \
            open(log_file, "a+", encoding="UTF-8") as logs_file:

        # Apparently there is no mode to open/create a file for read/write from the beginning
        # so we have to manually position the cursor
        processed_repos_file.seek(0)
        processed_repos = tuple(processed_repos_file)
        processed_repos = list(map(lambda s: s.strip(), processed_repos))
        searcher.set_ignored(processed_repos)

        result_queue = Queue()

        i = 0
        for _ in range(workers):
            executor.submit(worker_fn, result_queue, searcher, search_conf)

        try:
            while True:
                repo, file_matches = result_queue.get(block=True)

                if len(file_matches) > 0:
                    write_to_file(logs_file, "##### Checked repository: %s" % repo.full_name)
                    write_to_file(logs_file, "### URL: %s" % repo.html_url)
                    write_to_file(logs_file, "### Description: %s" % repo.description)
                    for dname, fname, matches in file_matches:
                        write_to_file(logs_file, "\tPossibly vulnerable file: %s/%s" % (dname, fname))
                        for match in matches:
                            # truncate line to a max length of 150 characters
                            line = "\t\t%s" % match.decode("UTF-8")
                            line = (line[:150] + ' ...') if len(line) > 150 else line
                            write_to_file(logs_file, line)
                    write_to_file(logs_file, "")

                processed_repos_file.write(repo.full_name + "\n")
                processed_repos_file.flush()

        except KeyboardInterrupt as e:
            return


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("Please specify one of the following search config names:")
        for key in config.configs:
            print("  %15s: %s" % (key, config.configs[key].description))
        print("You are able to specify the upper date bound as second parameter in the format YYYY-MM-DD")
        sys.exit(1)

    search_conf = config.configs[sys.argv[1]]
    print("Using configuration: %s" % search_conf.name)

    if len(sys.argv) is 3:
        upper_date_limit = datetime.strptime(sys.argv[2], "%Y-%m-%d").date()
    else:
        upper_date_limit = datetime.now().date()

    ghub = Github(login_or_token=config.access_token, per_page=100)
    searcher = RepoSearcher(ghub, upper_date_limit, max_empty_months=12, languages=search_conf.languages,
                            **config.search_params)

    execute_search(search_conf, searcher, config.worker_count)
