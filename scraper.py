import re
from urllib.parse import urlparse, urldefrag
from bs4 import BeautifulSoup
from simhash import Simhash
import nltk
from collections import Counter
from nltk.corpus import stopwords
from nltk.tokenize import RegexpTokenizer
from urllib import robotparser
import hashlib

REPEATED_TRESH = 15

robots = {}
visited = {}
tokens = Counter()
largest_page = ""
largest_count = 0
subdomain_count = Counter()

prev = []
prevsimhash = []

def checksum(text):
    sum = 0
    for character in text.strip():
        sum += ord(character)
    return sum

def get_features(text):
    ret = []
    width = 3
    text = text.lower()
    text = re.sub(r'[^\w]+', '', text)
    for i in range(len(text) - width + 1):
        ret.append(text[i:i + width])
    return ret

def hash(tokens) -> int:
    weights = Counter()
    hashes = dict()
    combreversed = [0] * 256
    for token in tokens:
        weights[token] += 1
        hashed = hashlib.sha256(token)
        hashes[token] = hashed
    for k,v in hashes.items():
        num = int(v, 16)
        weight = weights[k]
        counter = 0
        while counter != 256:
            bit = num % 2
            if bit == 1:
                combreversed[counter] += weight
            else:
                combreversed[counter] -= weight
            num = num // 2
            counter += 1
    simhash_value = 0
    for bit in combreversed[::-1]:
        if bit > 0:
            simhash_value = simhash_value * 2 + 1
        else:
            simhash_value *= 2
    return simhash_value


def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]
   
def similiarity_check(text) -> bool:
    cur = checksum(text)
    cursimhash = Simhash(get_features(text))
    if any([cur == x for x in prev]):
        return True
    elif len(prevsimhash) > 0 and any(cursimhash.distance(x) <= 4 for x in prevsimhash):
        return True
    prev.append(cur)
    prevsimhash.append(cursimhash)
    return False 
   
def tokenize_and_count(text, url) -> list[str]:
    global largest_count, largest_page

    tokenizer = RegexpTokenizer(r'\w+')
    page_tokens = tokenizer.tokenize(text.lower())
    #pageTokens = nltk.word_tokenize(text)
    stop_words = set(stopwords.words('english'))
    punctuation = {",",".","{","}","[","]","|","(",")","<",">"}
    stop_words = stop_words.union(punctuation)
    word_count = 0
    for w in page_tokens:
        if w not in stop_words:
            word_count += 1
            tokens[w.lower()] += 1

    if word_count > largest_count:
        largest_count = word_count 
        largest_page = url
    return page_tokens

def check_sitemaps(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    if domain not in robots:
        robotparse = robotparser.RobotFileParser(parsed.scheme + "://" + domain + "/robots.txt")
        robotparse.read()
        return robotparse.site_maps()
    return []

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content

    # didn't get the page, so return empty list

    if resp.status != 200:
        print(resp.url, resp.error)
        return []
    elif not resp.raw_response:
        print(resp.url, "none response")
        return []
    elif resp.status == 200 and resp.raw_response.content is None:
        print(resp.url, "no content")
        return []

    parsed_html = BeautifulSoup(resp.raw_response.content, "lxml")
    text = parsed_html.get_text()

    
    page_tokens = tokenize_and_count(text, url)
    
    if similiarity_check(text):
        return []

    additional_pages = check_sitemaps(url)
    
    return [get_absolute_path(link.get("href"), resp.url) for link in parsed_html.find_all("a")] + additional_pages




def in_domain_scope(parsed):
    for domain in [".ics.uci.edu", ".cs.uci.edu", ".informatics.uci.edu", ".stat.uci.edu"]:
        if parsed.netloc.endswith(domain):
            return True
    return False

def check_robots(parsed):
    # disallowed robots.txt urls/paths
    domain = parsed.netloc
    if domain not in robots:
        robotparse = robotparser.RobotFileParser(parsed.scheme + "://" + domain + "/robots.txt")
        try:
            robotparse.read()
            robots[domain] = robotparse
            return robotparse
        except:
            robots[domain] = None
            return None
    else:
        return robots[domain]

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.

    global robots

    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        if not in_domain_scope(parsed):
            return False
        
        robotparse = check_robots(parsed)
        
        if robotparse and not robotparse.can_fetch("*", url):
            return False
        
        if is_trap(url):
            return False

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise

'''
Check the given url, see if its relative or absolute path.
If relative, make the conversion and return the path.
If absolute, just return the path.
'''
def get_absolute_path(path: str, current_url: str) -> str:
    # can an empty string be in the href?
    if path == None:
        path = ""
    path = urldefrag(path)[0]
    parsed_path = urlparse(path)
    # is absolute path
    if parsed_path.scheme:
        return path
    # is partially absolute
    elif parsed_path.netloc:
        return "http" + path
    # is relative
    else:
        return current_url.rstrip("/") + path
    

'''
Check url pattern to make sure does not lead to a trap
'''
def is_trap(url):
    parsed = urlparse(url)
    base = parsed.scheme + '://' + parsed.netloc + parsed.path
    path_list = parsed.path.split("/")
    same_count = Counter(path_list)
    if same_count.most_common(1)[0][1] > 3:
        return True

    if base in visited:
        visited[base] += 1
        if visited[base] > REPEATED_TRESH:
            return True
        else:
            return False
    else:
        visited[base] = 1
        return False

def subdomain_pages(urls: set) -> None:
    global subdomain_count
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.endswith(".ics.uci.edu") and domain != "www.ics.uci.edu":
            subdomain_count[domain] += 1


def summary():
    for token, freq in tokens.most_common(50):
        print(token, freq)
    print(largest_page +": ", largest_count)
    subdomain_pages(visited)
    print(sorted(subdomain_count.items()))


def sitemaps(robotParser):
    if robotParser.site_maps() != None:
        return robotParser.site_maps()
    else:
        return []
    
