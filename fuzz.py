import sys
sys.dont_write_bytecode = True

import argparse
from tldextract import extract
from Crawler import URL
from Search.attack import VulnFuzz

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help='input URL', dest='url')

    args = parser.parse_args()
    url = args.url

    if url:
        domain = extract(url).domain
        Crawling = URL(url, **{})
        Crawling.Crawler()
        Crawling.closed()
        print('-done-')
        VulnFuzz(domain, **{})