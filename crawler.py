#
# Crawler for vulnerabilities on GitHub
#


# IMPORTS
import os
import sys
import time
import mmap
from queue import Queue
from concurrent.futures import ThreadPoolExecutor

from git import Git
from github import Github
from shutil import rmtree

import config
import threading


class PrintThread(threading.Thread):
    def __init__(self, queue, output, printToStdin=False):
        threading.Thread.__init__(self)
        self.queue = queue
        self.output = output
        self.printToStdin = printToStdin
        if not os.path.exists(self.output):
            with open(self.output, "w") as file:
                file.write("")

    def print_line(self, line):
        with open(self.output, "a", encoding="UTF-8") as file:
            file.write(line + "\n")
        if self.printToStdin:
            print(line)

    def run(self):
        while True:
            result = self.queue.get()
            self.print_line(result)
            self.queue.task_done()


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
            if os.stat(fpath).st_size > 0 and fname.endswith(filetypes):
                matches = check_file(fpath, search_pattern)

                # Only append files which actually have any matches
                if len(matches) > 0:
                    results.append((dname[len(folder) + 1:], fname, matches))
    return results


def check_repository(repo, search_conf):
    try:

        path = clone_repository("tmp", repo)
        metadata = {
            "description": repo.description,
            "url": repo.html_url
        }
        results = check_folder(path, search_conf)
        rmtree(path)
        return (path, metadata, results)

    except Exception as e:
        print("Exception occurred while searching: %s" % e)


def check_folder(path, search_conf):
    results = search_folder(path, search_conf.filetypes, search_conf.regex)
    return results


def clone_repository(rootdir, repo):
    base_dir = "%s/%s" % (rootdir, repo.full_name.split("/")[0])
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
    Git(base_dir).clone(repo.clone_url, "--depth", "1")
    return "%s/%s" % (rootdir, repo.full_name)


def build_query(stars, last_accessed, max_size, language):
    query = "stars:%i..%i pushed:>%s size:<%i language:%s" % (
        stars[0], stars[1], last_accessed, max_size, language
    )
    return query


def print_results(print_queue, path, metadata, results):
    if len(results) > 0:
        print_queue.put("##### Results for: %s" % path[4:])  # remove tmp/ prefix
        if metadata:
            print_queue.put("## URL: %s" % metadata["url"])
            print_queue.put("## Description: %s" % metadata["description"])
        for dname, fpath, matches in results:
            print_queue.put("Possibly vulnerable file: %s/%s" % (dname, fpath))
            for match in matches:
                print_queue.put("\t%s" % match.decode("UTF-8"))
        print_queue.put("")


def handle_repository(repo, search_conf, file_queue=None, print_queue=None):
    tuple = check_repository(repo, search_conf)

    if file_queue:
        file_queue.put(repo.full_name)
    if print_queue:
        print_results(print_queue, tuple[0], tuple[1], tuple[2])


def execute_search(repos, search_conf, workers):
    if not os.path.exists(config.processed_base_dir):
        os.makedirs(config.processed_base_dir)

    print_queue = Queue()
    file_queue = Queue()

    if not os.path.exists(config.logs_base_dir):
        os.makedirs(config.logs_base_dir)
    if not os.path.exists(config.processed_base_dir):
        os.makedirs(config.processed_base_dir)

    log_file = "%s/%s" % (config.logs_base_dir, search_conf.log)
    cache_file = "%s/%s" % (config.processed_base_dir, search_conf.processed)

    p = PrintThread(print_queue, log_file, True)
    p.setDaemon(True)
    p.start()

    f = PrintThread(file_queue, cache_file)
    f.setDaemon(True)
    f.start()

    with open(cache_file, "r") as file:
        lines = tuple(file)
        lines = list(map(lambda s: s.strip(), lines))  # Remove newline characters

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for repo in repos:
            if not repo.full_name in lines:
                executor.submit(handle_repository, repo, search_conf, file_queue, print_queue)


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
