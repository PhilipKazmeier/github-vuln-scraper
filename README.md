# GitHub Vulnerability Scraper

This vulnerability scraper for GitHub was developed as part of a lecture at the **TU Darmstadt**.

### Setup
The crawler uses [direnv] for the python environment.

```
direnv allow
pip3 install requirements.txt
```


### Usage
Please replace the *PERSONAL_ACCESS_TOKEN* in conf/config.py with your own [Github Personal Access Token][perstokenlink].

By running `python3 crawler.py` all possible configurations will be displayed.

Select one of the configurations and provide it as input to the script like `python3 crawler.py name_of_config`.

The crawler will then start running and outputs any results to the corresponding file in the *logs* folder.


[perstokenlink]: https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/
[direnv]: https://direnv.net/
