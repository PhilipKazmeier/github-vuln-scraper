import time
import threading
from datetime import datetime, timedelta


def _get_date_of_previous_month(date):
    one_day = timedelta(days=1)
    one_month_earlier = date - one_day
    while one_month_earlier.month == date.month or one_month_earlier.day > date.day:
        one_month_earlier -= one_day
    return one_month_earlier


def _build_query(stars=None, forks=None, last_accessed=None, max_size=None, languages=None, topics=None, org=None,
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


def _get_utc_timestamp():
    return int((datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0, 0)).total_seconds())


class RepoSearcher:
    """
    Helper class for looping through repositories queried from GitHub.
    This class is optimized to work in a multithreaded context and can be used in such without any further modifications.
    """

    def __init__(self, ghub, search_date=datetime.now().date(), max_empty_months=0, ignored_repos=None, **kwargs):
        """
        Creates a new RepoSearcher.
              
        :param ghub: Authenticated GitHub instance 
        :param search_date: Date that determines before which date the search will start (Default: today)
        :param max_empty_months: Allowed number of consecutive months without repository results (Default: 0)
        :param ignored_repos: List of repositories that should be ignored (Default: Empty List)
        :param kwargs: Arguments used for the GitHub query building
        """
        if ignored_repos is None:
            ignored_repos = []
        self._ghub = ghub
        self._cur_date = search_date
        self._max_empty_months = max_empty_months
        self._search_params = kwargs
        self._ignored_repos = ignored_repos

        self._lock = threading.RLock()
        self._cur_repos = None
        self._cur_index = 0

    def set_ignored(self, repos):
        """
        Overrides the list of ignored repositories used in the RepoSearcher.
        
        :param repos: List of repositories to ignore
        """
        self._lock.acquire()
        try:
            self._ignored_repos = repos
        finally:
            self._lock.release()

    def get_next(self):
        self._lock.acquire()
        try:
            return self._find_next_new()
        finally:
            self._lock.release()

    def _find_next_new(self):
        while True:
            repo = self._do_get_next()
            if repo is None or repo.full_name not in self._ignored_repos:
                return repo

    def _do_get_next(self):
        self._wait_for_quota()
        if not self._list_has_next():
            if not self._find_next_nonempty_month():
                return None
        return self._list_get_next()

    def _list_has_next(self):
        return self._cur_repos is not None and self._cur_index < self._cur_repos.totalCount

    def _list_get_next(self):
        item = self._cur_repos[self._cur_index]
        self._cur_index += 1
        return item

    def _find_next_nonempty_month(self):
        for _ in range(self._max_empty_months + 1):
            self._load_next_month()
            if self._list_has_next():
                return True
        return False

    def _load_next_month(self):
        end_date = self._cur_date
        start_date = _get_date_of_previous_month(end_date) + timedelta(days=1)

        query = _build_query(created=(start_date, end_date), **self._search_params)
        self._cur_repos = self._ghub.search_repositories(query=query, sort='stars', order='desc')
        self._cur_index = 0
        self._cur_date = start_date

    def _wait_for_quota(self):
        remaining_tries = self._ghub.rate_limiting[0]
        seconds_to_reset = max(self._ghub.rate_limiting_resettime - _get_utc_timestamp(), 0)

        if remaining_tries < 2:
            time.sleep(seconds_to_reset + 1)
