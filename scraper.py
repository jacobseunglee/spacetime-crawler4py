import re
from urllib.parse import urlparse, urldefrag, urljoin
from bs4 import BeautifulSoup
from simhash import Simhash
import nltk
from collections import Counter
from nltk.corpus import stopwords
from nltk.tokenize import RegexpTokenizer
from urllib import robotparser
import hashlib
import json
import os

REPEATED_THRESH = 21

robots = {}
visited = set()
tokens = {}
largest_page = ""
largest_count = 0

prev = []
prev_simhash = []
visit_count = {}


def json_save():
    dictionary = {
        "visited" : list(visited),
        "tokens" : dict(tokens),
        "largest_page" : largest_page,
        "largest_count" : largest_count,
        "prev" : prev,
        "prev_simhash" : prev_simhash,
        "visit_count" : visit_count
    }
    json_object = json.dumps(dictionary, indent=4)
    with open("save.json", "w") as f:
        f.write(json_object)

def load_saved_vars():
    global visited, tokens, largest_page, largest_count, prev, prev_simhash, visit_count
    with open("save.json", "r") as save:
        data = save.read()
        json_object = json.loads(data)
        visited = set(json_object["visited"])
        tokens = json_object["tokens"]
        largest_page = json_object["largest_page"]
        largest_count = json_object["largest_count"]
        prev = json_object["prev"]
        prev_simhash = json_object["prev_simhash"]
        visit_count = json_object["visit_count"]

def checksum(tokens):
    sum = 0
    for token in tokens:
        for character in token:
            sum += ord(character)
    return sum

def hash(weights) -> int:
    hashes = dict()
    combreversed = [0] * 256
    for token in weights:
        hashed = hashlib.sha256(token.encode())
        hashes[token] = hashed
    for k,v in hashes.items():
        num = int(v.hexdigest(), 16)
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

def hash_distance(hash1, hash2):
    return bin(hash1 ^ hash2).count('1')


'''
Just a helper for now, modify the integer after <=
'''
def determine_distance(target):
    i = -1
    for prev in prev_simhash:
        i += 1
        calc = hash_distance(prev, target)
        if calc <= 20:
            print('------------- found similar simhash at i =', i, '-------------')
            return True
    print('############## no similar simhash ##############')
    return False


def scraper(url, resp):
    if os.path.exists("save.json") and prev == []:
        load_saved_vars()
    visited.add(url)
    links = extract_next_links(url, resp)
    json_save()
    return [link for link in links if is_valid(link)]
   
def similarity_check(tokens) -> bool:
    cur = checksum(tokens)
    # if len(prevsimhash) > 0 and any(hash_distance(x, cursimhash) <= 4 for x in prevsimhash):
    if any([cur == x for x in prev]):
        print('---------- found same checksum -----------------')
        return True
    cur_simhash = hash(tokens)
    if len(prev_simhash) and determine_distance(cur_simhash):
        return True
    prev_simhash.append(cur_simhash)
    prev.append(cur)
    return False 
   
def tokenize_and_count(text, url) -> list[str]:
    global largest_count, largest_page

    tokenizer = RegexpTokenizer(r'\w{2,}')
    page_tokens = tokenizer.tokenize(text.lower())
    #pageTokens = nltk.word_tokenize(text)
    stop_words = set(stopwords.words('english'))
    punctuation = {",",".","{","}","[","]","|","(",")","<",">"}
    stop_words = stop_words.union(punctuation)
    word_count = 0
    for w in page_tokens:
        if w not in stop_words:
            word_count += 1
            if w not in tokens:
                tokens[w] = 1
            else:
                tokens[w] = int(tokens[w]) + 1

    if word_count > largest_count:
        largest_count = word_count 
        largest_page = url
    return page_tokens

def has_low_information(unique, length):
    return unique / length < .2 if length > 0 else False

def check_sitemaps(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    if domain not in robots:
        robotparse = robotparser.RobotFileParser(parsed.scheme + "://" + domain + "/robots.txt")
        robotparse.read()
        ret = robotparse.site_maps()
        return ret if ret else []
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

    if resp.status >300 and resp.status < 310:
         print("****", resp.url, "***", resp.raw_response.url)
         if is_valid(resp.raw_response.url):
            return [resp.raw_response.url]
    if resp.status != 200:
        print(resp.url, resp.error)
        return []
    elif not resp.raw_response:
        print(resp.url, "none response")
        return []
    elif resp.status == 200 and resp.raw_response.content is None:
        print(resp.url, "no content")
        return [] 
    if url != resp.raw_response.url.rstrip("/"): 
        return [resp.raw_response.url]
    
    parsed_html = BeautifulSoup(resp.raw_response.content, "lxml")
    text = parsed_html.get_text()

    if url.endswith('.xml'):
        return [get_absolute_path(link.text, resp.raw_response.url) for link in parsed_html.find_all("loc")]
    
    page_tokens = tokenize_and_count(text, url)
    token_counter = Counter(page_tokens)
    
    if similarity_check(token_counter):
        return []
    
    # we have to avoid crawling low information, so maybe just has_low_information is enough
    if has_low_information(len(token_counter), len(page_tokens)):
        return []

    additional_pages = check_sitemaps(url)
    
    return [get_absolute_path(link.get("href"), resp.raw_response.url) for link in parsed_html.find_all("a")] + additional_pages




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
        
        if is_query_trap(url):
            return False
        
        if is_recursive_trap(url):
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
    path = urldefrag(path)[0]
    return urljoin(current_url, path)
    

'''
Check url pattern to make sure does not lead to a trap
'''
def is_recursive_trap(url):
    parsed = urlparse(url)
    base = parsed.scheme + '://' + parsed.netloc + parsed.path
    path_list = parsed.path.split("/")
    same_count = Counter(path_list)
    if same_count.most_common(1)[0][1] > 3:
        return True
    return False

def is_query_trap(url):
    global visit_count
    parsed = urlparse(url)
    base = parsed.scheme + '://' + parsed.netloc + parsed.path
    if base not in visit_count:
        visit_count[base] = 0
    visit_count[base] = int(visit_count[base]) + 1
    return visit_count[base] > REPEATED_THRESH

def subdomain_pages(urls: set) -> None:
    subdomain_count = Counter()
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.endswith(".ics.uci.edu") and domain != "www.ics.uci.edu":
            subdomain_count[domain] += 1
    return subdomain_count

def summary():
    max_tokens = [(k,v) for k, v in sorted(tokens.items(),key = lambda x: -1 * int(x[1]))]
    for token, freq in max_tokens[:100]:
        print(token, freq)
    print(largest_page +": ", largest_count)
    subdomain_count = subdomain_pages(visited)
    print(sorted(subdomain_count.items()))


def sitemaps(robotParser):
    if robotParser.site_maps() != None:
        return robotParser.site_maps()
    else:
        return []
    
