#
# Crawler for vulnerabilities on GitHub
#


# IMPORTS
import os
import sys
import mmap
import queue
from concurrent.futures import ThreadPoolExecutor

from git import Git
from github import Github
from shutil import rmtree

import config


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
        map = mmap.mmap(fileno=f.fileno(), length=0, prot=mmap.PROT_READ)
        return check_contents(map, search_pattern)


def check_folder(folder, filetypes, search_pattern):
    # Check if the given folder contains any files with matches for one of our vunerabilities
    results = []
    for dname, _, files in os.walk(folder):
        for fname in files:
            fpath = os.path.join(dname, fname)
            if os.stat(fpath).st_size > 0 and has_filetype(fname, filetypes):
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


def clone_repository(rootdir, repo):
    repo_path = "%s/%s" % (rootdir, repo.full_name)
    if not os.path.exists(repo_path):
        os.makedirs(repo_path)
    Git(repo_path).clone(repo.clone_url, "--depth", "1")
    return repo_path


def check_repository(repo, search_conf):
    try:
        path = clone_repository("tmp", repo)
        results = check_folder(path, search_conf.filetypes, search_conf.regex)
        rmtree(path)

        return repo.full_name, results
    except Exception as e:
        print("Exception occurred while searching: %s" % e)
        return repo.full_name, []


def worker_fn(result_queue, repo_queue, search_conf):
    while True:
        repo = repo_queue.get(block=True)
        if repo is None:
            break
        result = check_repository(repo, search_conf)
        result_queue.put(result)

        repo_queue.task_done()


def execute_search(repos, search_conf, workers):
    if not os.path.exists(config.logs_base_dir):
        os.makedirs(config.logs_base_dir)
    if not os.path.exists(config.processed_base_dir):
        os.makedirs(config.processed_base_dir)
    log_file = "%s/%s" % (config.logs_base_dir, search_conf.log)
    cache_file = "%s/%s" % (config.processed_base_dir, search_conf.processed)

    with ThreadPoolExecutor() as executor, open(cache_file, "a") as processed_repos_file, \
        open(log_file, "a", encoding="UTF-8") as logs_file:
        processed_repos = tuple(processed_repos_file)
        processed_repos = list(map(lambda s: s.strip(), cached_repos))

        repo_queue = queue.Queue()
        result_queue = queue.Queue()

        i = 0
        submitted = 0
        while submitted < workers:
            if repos[i].full_name in processed_repos:
                repo_queue.put(repos[i])
                executor.submit(worker_fn, result_queue, repo_queue, search_conf)
                submitted += 1
            i += 1

        try:
            while True:
                repo_name, file_matches = result_queue.get(block=True)

                logs_file.write("Checked repository: %s" % repo_name)
                for fname, matches in file_matches:
                    logs_file.write("Possibly vulnerable file: %s" % fname)
                    for match in matches:
                        logs_file.write("\t%s" % match)
                logs_file.write("")

                repo_queue.put(repos[i])
                i += 1

        except KeyboardInterrupt as e:
            # Put empty items into the queue to signal shutdown
            map(repo_queue.put, [None] * workers)


def build_query(stars=None, last_accessed=None, max_size=None, language=None):
    query = ""
    if stars is not None:
        query = query + "stars:%i..%i " % stars
    if last_accessed is not None:
        query = query + "pushed:>%s " % last_accessed
    if max_size is not None:
        query = query + "size:<%i " % max_size
    if language is not None:
        query = query + "language:%s " % language

    return query


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
