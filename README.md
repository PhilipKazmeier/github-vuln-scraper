# GitHub Vulnerability Scraper

This vulnerability scraper for GitHub was developed as part of a lecture at the **TU Darmstadt**.

### Setup
```
direnv allow
pip3 install requirements.txt
```


### Usage
Please replace the *access_token* in conf/config.py with your own Github API Access Token.

By running `python3 crawler.py` all possible configurations will be displayed.

Select one of the configurations and provide it as input to the script like `python3 crawler.py name_of_config`.

The crawler will then start running an outputting any results to the corresponding file in the *logs* folder.