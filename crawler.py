#
# Crawler for vulnerabilities on GitHub
#


# IMPORTS
import os
import sys
import time
import mmap
from queue import Queue
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from git import Git
from github import Github, RateLimitExceededException
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
        fmap = mmap.mmap(fileno=f.fileno(), length=0, prot=mmap.PROT_READ)
        return check_contents(fmap, search_pattern)


def check_folder(folder, file_types, search_pattern):
    # Check if the given folder contains any files with matches for one of our vunerabilities
    results = []
    for dname, _, files in os.walk(folder):
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
        os.makedirs(clone_path)
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


def worker_fn(result_queue, repo_queue, search_conf):
    while True:
        repo = repo_queue.get(block=True)
        if repo is None:
            break
        result = check_repository(repo, search_conf)
        result_queue.put(result)

        repo_queue.task_done()


def print_and_log(output_file, data):
    # Print the given data to stdout and to the given file
    print(data)
    output_file.write(data + "\n")
    output_file.flush()


def find_next_unprocessed_safely(repos, processed_repos, i):
    # Return the next repository that has not already been processed (is not in processed_repos)
    while True:
        repo = access_list_safely(repos, i)
        if repo is None or repo.full_name not in processed_repos:
            return i + 1, repo
        i += 1


def access_list_safely(lizt, index):
    while True:
        try:
            # If the total count of the lizt is exceeded or the total count of the API is exceeded return None to
            # trigger a reload of the repos
            if index >= min(lizt.totalCount, 1000):
                return None
            return lizt[index]
        except RateLimitExceededException:
            print("Rate limit exceeded, sleeping for short duration!", file=sys.stderr)
            time.sleep(5)


def get_utc_timestamp():
    return int((datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0, 0)).total_seconds())


def limit_rate(ghub):
    remaining_tries = ghub.rate_limiting[0]
    seconds_to_reset = max(ghub.rate_limiting_resettime - get_utc_timestamp(), 0)

    if remaining_tries < 1:
        print("Rate limit exceeded - sleeping until reset!")
        time.sleep(seconds_to_reset)


def getDateOfPreviousMonth(date):
    one_day = timedelta(days=1)
    one_month_earlier = date - one_day
    while one_month_earlier.month == date.month or one_month_earlier.day > date.day:
        one_month_earlier -= one_day
    return one_month_earlier


def getRepos(ghub, search_conf, to_date):
    from_date = getDateOfPreviousMonth(to_date)
    query = build_query(languages=search_conf.languages, **config.search_params, created=(from_date, to_date))
    return ghub.search_repositories(query=query, sort='stars', order='desc'), from_date


def execute_search(ghub, search_conf, workers):
    if not os.path.exists(config.logs_base_dir):
        os.makedirs(config.logs_base_dir)
    if not os.path.exists(config.processed_base_dir):
        os.makedirs(config.processed_base_dir)
    log_file = "%s/%s.log" % (config.logs_base_dir, search_conf.name)
    cache_file = "%s/%s.txt" % (config.processed_base_dir, search_conf.name)

    repos, last_date = getRepos(ghub, search_conf, datetime.today().date())

    with ThreadPoolExecutor() as executor, open(cache_file, "a+") as processed_repos_file, \
            open(log_file, "a+", encoding="UTF-8") as logs_file:

        # Apparently there is no mode to open/create a file for read/write from the beginning
        # so we have to manually position the cursor
        processed_repos_file.seek(0)
        processed_repos = tuple(processed_repos_file)
        processed_repos = list(map(lambda s: s.strip(), processed_repos))

        repo_queue = Queue()
        result_queue = Queue()

        i = 0
        for _ in range(workers):
            next_repo = None
            while next_repo is None:
                i, next_repo = find_next_unprocessed_safely(repos, processed_repos, i)
                # If no new repo was found, load repos of previous month
                if next_repo is None:
                    repos, last_date = getRepos(ghub, search_conf, last_date)
                    i = 0
            repo_queue.put(next_repo)
            executor.submit(worker_fn, result_queue, repo_queue, search_conf)

        try:
            while True:
                repo, file_matches = result_queue.get(block=True)

                if len(file_matches) > 0:
                    print_and_log(logs_file, "##### Checked repository: %s" % repo.full_name)
                    print_and_log(logs_file, "### URL: %s" % repo.html_url)
                    print_and_log(logs_file, "### Description: %s" % repo.description)
                    for dname, fname, matches in file_matches:
                        print_and_log(logs_file, "Possibly vulnerable file: %s/%s" % (dname, fname))
                        for match in matches:
                            # truncate line to a max length of 100 characters
                            line = "\t%s" % match.decode("UTF-8")
                            line = (line[:100] + '..') if len(line) > 100 else line
                            print_and_log(logs_file, line)
                    print_and_log(logs_file, "")

                limit_rate(ghub)
                processed_repos_file.write(repo.full_name + "\n")
                processed_repos_file.flush()
                next_repo = None
                while next_repo is None:
                    i, next_repo = find_next_unprocessed_safely(repos, processed_repos, i)
                    # If no new repo was found, load repos of previous month
                    if next_repo is None:
                        repos, last_date = getRepos(ghub, search_conf, last_date)
                        i = 0
                repo_queue.put(next_repo)

        except KeyboardInterrupt as e:
            # Put empty items into the queue to signal shutdown
            map(repo_queue.put, [None] * workers)


def build_query(stars=None, forks=None, last_accessed=None, max_size=None, languages=None, topics=None, org=None,
                user=None, created=None):
    query = ""
    if stars is not None:
        query = query + "stars:%i..%i " % stars
    if forks is not None:
        query = query + "forks:%i..%i " % forks
    if last_accessed is not None:
        query = query + "pushed:>%s " % last_accessed
    if max_size is not None:
        query = query + "size:<%i " % max_size
    if languages is not None:
        for language in languages:
            query = query + "language:%s " % language
    if topics is not None:
        for topic in topics:
            query = query + "topic: %s " % topic
    if org is not None:
        query = query + "org: %s " % org
    if user is not None:
        query = query + "user: %s " % user
    if created is not None:
        query = query + "created:%s..%s" % created

    return query


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("Please specify one of the following search config names:")
        for key in config.configs:
            print("  %10s: %s" % (key, config.configs[key].description))
        sys.exit(1)

    search_conf = config.configs[sys.argv[1]]
    print("Using configuration: %s" % search_conf.name)

    ghub = Github(login_or_token=config.access_token)

    execute_search(ghub, search_conf, config.worker_count)
