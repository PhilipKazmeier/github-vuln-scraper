from config import credentials, ignored_repos

from github import Github
from github.GithubException import RateLimitExceededException
from time import sleep
from git import Git
from shutil import rmtree
import sys
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor

access_token = credentials["access_token"]
g = Github(login_or_token=access_token)

'''
# invalid search characters
# . , : ; / \ ` ' " = * ! ? # $ & + ^ | ~ < > ( ) { } [ ]

sql_injection_query = 'SELECT FROM WHERE NOT "bind_param" NOT "prepare" extension:php in:file'
buffer_overflow_query = 'sprintf OR scanf extension:c extension:cpp in:file'


code_snippets = g.search_code(query=sql_injection_query, sort='indexed', order='desc')



def check_code(snippets):
    last_repo = ""
    print("Starting")
    total = 0
    count = 0
    for snippet in snippets:
        if snippet.repository.full_name in ignored_repos['sql_injection']:
            continue
        total = total + 1
        if last_repo != snippet.repository.full_name:
            sys.stdout.write(".")
            sys.stdout.flush()
            count = count + 1
            if count == 100:
                print('\n')
                count = 0
        if 50 < snippet.repository.stargazers_count:
            count = 0
            if last_repo != snippet.repository.full_name:
                last_repo = snippet.repository.full_name
                print("\nFound match in repo %s " % last_repo)
            print("\tIn File: %s " % snippet.path)
    print("Worked over %d of %d" % (total, snippets.totalCount))


check_code(code_snippets.get_page(111111))


thread_count = 2
total = code_snippets.totalCount
steps = int(total / thread_count)

for i in range(thread_count):
    threading.Thread(target=check_code, kwargs={'snippets': code_snippets[steps*i:steps*(i+1)-100]}).start()

'''

SQL_INJECTION_STRING = "(.*(SELECT|INSERT).* \$_GET\[\".*\"\])"

pattern = re.compile(SQL_INJECTION_STRING)


def check_code(folder):
    # print("Checking %s" % folder)
    for dname, dirs, files in os.walk(folder):
        for fname in files:
            fpath = os.path.join(dname, fname)
            if fpath.endswith(".php"):
                with open(fpath, encoding="UTF-8") as f:
                    # print("Checking %s " % f)
                    for i, line in enumerate(f):
                        for match in re.finditer(pattern, line):
                            print('\tFound on line %s: %s' % (i + 1, match.groups()))


def check_repo(repo):
    print("Searching in %s" % repo.full_name)
    if not os.path.exists("tmp/%s" % repo.full_name):
        os.makedirs("tmp/%s" % repo.full_name)
    Git("tmp/%s" % repo.full_name).clone(repo.clone_url)
    check_code("tmp/%s" % repo.full_name)
    rmtree("tmp/%s" % repo.full_name)
    print("Finished %s" % repo.full_name)


# Search all repositories with:
# - 75 to 150 stars
# - updated in the last 12 months
repos = g.search_repositories(query='stars:75..150 pushed:>2017-01-08 language:php', sort='stars', order='asc')

i = 0
with ThreadPoolExecutor(max_workers=8) as executer, open("processed_repos.txt", "r+") as file:
    lines = tuple(file)
    for repo in repos:
        if not lines.__contains__(repo.full_name):  # TODO fix
            file.write(repo.full_name + "\n")
            executer.submit(check_repo, repo)
            i = i+1
            if i == 5:
                break

