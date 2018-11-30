# Capsula - Amr Abed's Blog
[![Blog](https://img.shields.io/website-up-down-brightgreen-red/https/amrabed.me/blog.svg?label=blog.amrabed.me)](https://amrabed.me/blog)
[![Build Status](https://travis-ci.org/amrabed/blog.svg?branch=master)](https://travis-ci.org/amrabed/blog)
[![Code Quality](https://sonarcloud.io/api/project_badges/measure?project=blog.amrabed.me&metric=alert_status)](https://sonarcloud.io/dashboard?id=blog.amrabed.me)
[![Known Vulnerabilities](https://snyk.io/test/github/amrabed/blog/badge.svg?targetFile=Gemfile.lock)](https://snyk.io/test/github/amrabed/blog?targetFile=Gemfile.lock)
[![GitHub issues](https://img.shields.io/github/issues/amrabed/blog.svg)](https://github.com/amrabed/blog/issues)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
## Usage 
### Build using Bundler
```
bundle install && jekyll build [-d <webroot>/blog] [--watch]
```
This adds built blog files into the specified folder if any, 
or the default `./_site` otherwise.
### Build using Docker
Edit [this line](docker-compose.yml#L9) of [docker-compose.yml](docker-compose.yml) with your destination folder,
 and use `docker-compose up -d`. Alternatively, use:
```
export BLOG_DIR='<webroot>/blog' && docker-compose up -d
```
This adds built blog files into the specified folder.