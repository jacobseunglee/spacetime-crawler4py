import re
from urllib.parse import urlparse, urldefrag, urljoin, ParseResult
from bs4 import BeautifulSoup
import nltk
from collections import Counter
from nltk.corpus import stopwords
from nltk.tokenize import RegexpTokenizer
from urllib import robotparser
import hashlib
import json
import os
from utils.response import Response

REPEATED_THRESH = 21

# dictionary to parse robots.txt pages - {domain : RobotFileParser}
robots = {} 
# set of visited pages
visited = set()
# Counter of tokens
tokens = {}
# the longest page in terms of number of words/tokens
largest_page = ""
# the number of words/tokens of the longest page
largest_count = 0

# record of checksums of visited pages
prev = []
# record of simhashes of visited pages
prev_simhash = []
# counter for how many times we visited a page (excluding queries + fragments)
visit_count = {}
# record of domains where its sitemaps were visited
past_sitemaps = []
# number of pages that were "valid" - that returned status code 200 and weren't redirects
valid_page_count = 0


def json_save() -> None:
    '''
    Save global variables into a json file
    '''
    dictionary = {
        "visited" : list(visited),
        "tokens" : dict(tokens),
        "largest_page" : largest_page,
        "largest_count" : largest_count,
        "prev" : prev,
        "prev_simhash" : prev_simhash,
        "visit_count" : visit_count,
        "past_sitemaps": past_sitemaps,
        "valid_page_count": valid_page_count
    }
    json_object = json.dumps(dictionary, indent=4)
    with open("save.json", "w") as f:
        f.write(json_object)

def load_saved_vars() -> None:
    '''
    Load global variables by using data stored in json file
    '''
    global visited, tokens, largest_page, largest_count, prev, prev_simhash, visit_count, past_sitemaps, valid_page_count
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
        past_sitemaps = json_object["past_sitemaps"]
        valid_page_count = json_object["valid_page_count"]

def checksum(tokens: Counter[str, int]) -> int:
    '''
    Given the tokens of a page, calculate checksum of a page by
    adding the ASCII code of every character in the page.
    '''
    sum = 0
    for token in tokens:
        for character in token:
            sum += ord(character)
    return sum

def hash(weights: Counter[str, int]) -> int:
    '''
    Given a Counter that stores how many times each token appeared in a page,
    calculate the simhash value of the page.
    '''
    hashes = dict()
    combreversed = [0] * 256 # result of hash would be 256 bits
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

def hash_distance(hash1: int, hash2: int) -> int:
    '''
    Given two simhash values, calculate the distance between the two
    '''
    return bin(hash1 ^ hash2).count('1')


def determine_distance(target: int) -> bool:
    '''
    Given a simhash value of page, iterate through the simhash values
    of pages visited previously. Return True if there a page with a simhash 
    value with a distance <= 20.
    '''
    i = -1
    for prev in prev_simhash:
        i += 1
        calc = hash_distance(prev, target)
        if calc <= 20:
            print('------------- found similar simhash at i =', i, '-------------')
            return True
    print('############## no similar simhash ##############')
    return False


def scraper(url: str, resp: Response) -> list[str]:
    '''
    Given a url and the response from a get request to the url,
    scrape the page corresponding to the url and return a list of
    valid links the page has.
    '''
    if os.path.exists("save.json") and prev == []:
        load_saved_vars()
    visited.add(url)
    links = extract_next_links(url, resp)
    json_save()
    return [link for link in links if is_valid(link)]
   
def similarity_check(tokens: Counter[str, int]) -> bool:
    '''
    Given a list of a page's tokens, check if we previously visited a page
    similar to the one we are checking. Return True if a similar page was found.
    '''
    # checksum method - exact similarity
    cur = checksum(tokens)
    if any([cur == x for x in prev]):
        print('---------- found same checksum -----------------')
        return True
    # simhash method - near similarity
    cur_simhash = hash(tokens)
    if len(prev_simhash) and determine_distance(cur_simhash):
        return True
    
    prev_simhash.append(cur_simhash)
    prev.append(cur)
    return False 
   
def tokenize_and_count(text: str, url: str) -> list[str]:
    '''
    Given the url and textual content of a page, return a list of all
    the tokens of that page of length 2 or more.
    '''
    global largest_count, largest_page

    # we defined a token to be any alphanumeric sequence of length 2 or more
    tokenizer = RegexpTokenizer(r'\w{2,}')
    page_tokens = tokenizer.tokenize(text.lower())

    # words we do not want to keep track of in the global tokens counter
    stop_words = set(stopwords.words('english'))
    punctuation = {",",".","{","}","[","]","|","(",")","<",">"}
    stop_words = stop_words.union(punctuation)

    word_count = len(page_tokens)
    for w in page_tokens:
        if w not in stop_words:
            if w not in tokens:
                tokens[w] = 1
            else:
                tokens[w] = tokens[w] + 1

    # update largest page and size of largest page
    if word_count > largest_count:
        largest_count = word_count 
        largest_page = url
    return page_tokens

def has_low_information(unique: int, length: int) -> bool:
    '''
    Given the number of unqiue tokens and the total number of tokens of a page,
    determine if a page has low information.
    '''
    return (unique / length < .25 or unique / length >= 0.8) if length > 0 else False

def check_sitemaps(url: str) -> list[robotparser.RobotFileParser]:
    '''
    Given a url of a page, check if the sitemaps of the url's domain is visited.
    If visited, return empty list. 
    If not, return list of sitemaps in the domain's robots.txt file.
    '''
    parsed = urlparse(url)
    domain = parsed.netloc
    if domain not in past_sitemaps:
        past_sitemaps.append(domain)
        robotparse = robotparser.RobotFileParser(parsed.scheme + "://" + domain + "/robots.txt")
        robotparse.read()
        ret = robotparse.site_maps()
        return ret if ret else []
    return []

def extract_next_links(url: str, resp: Response) -> list[str]:
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content

    # didn't get the page, so return empty list

    global valid_page_count

    # first method of checking redirect
    # return the page that we are redirected to crawl later
    if resp.status >300 and resp.status < 310:
         print("****", resp.url, "***", resp.raw_response.url)
         if is_valid(resp.raw_response.url):
            return [resp.raw_response.url]
        
    # if the status code is not 200, we did not successfully get the page
    # do not crawl the page
    if resp.status != 200:
        print(resp.url, resp.error)
        return []
    # if there was no valid response, do not crawl the page
    elif not resp.raw_response:
        print(resp.url, "none response")
        return []
    # if there is a response but no content in the response, do not crawl the page
    elif resp.status == 200 and resp.raw_response.content is None:
        print(resp.url, "no content")
        return [] 
    
    # second method of checking redirect
    # 
    if url != resp.raw_response.url.rstrip("/"): 
        print('******* possible redirect found **************')
        return [resp.raw_response.url]
    
    parsed_html = BeautifulSoup(resp.raw_response.content, "lxml") # parse the content of response
    text = parsed_html.get_text()
    valid_page_count += 1

    # if the page was a sitemap
    if url.endswith('.xml'):
        return [get_absolute_path(link.text, resp.raw_response.url) for link in parsed_html.find_all("loc")]
    
    page_tokens = tokenize_and_count(text, url)
    token_counter = Counter(page_tokens)
    
    # check exact/near similarity with pages previously visited
    # do not crawl the page if an exact/near similarity is detected
    if similarity_check(token_counter):
        return []
    
    # if the page has low information value, do not crawl the page
    if has_low_information(len(token_counter), len(page_tokens)):
        return []

    # check if the sitemaps of the page's domain has been visited
    additional_pages = check_sitemaps(url)
    
    return [get_absolute_path(link.get("href"), resp.raw_response.url) for link in parsed_html.find_all("a")] + additional_pages




def in_domain_scope(parsed: ParseResult) -> bool:
    '''
    Given a parsed url make sure it is a domain that we want to search 
    return true if it is else return false
    '''
    for domain in [".ics.uci.edu", ".cs.uci.edu", ".informatics.uci.edu", ".stat.uci.edu"]:
        if parsed.netloc.endswith(domain):
            return True
    return False

def check_robots(parsed: ParseResult) -> robotparser.RobotFileParser:
    '''
    Given a parsed link if a new domain is reached update the robots dict to include 
    the RobotFileParser for the new domain. 
    Returns the RobotFileParser object if one exists else returns None
    '''
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

def is_valid(url: str) -> bool:
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.

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
        
        if is_query_trap(parsed):
            return False
        
        if is_recursive_trap(parsed):
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


def get_absolute_path(path: str, current_url: str) -> str:
    '''
    Check the given url, see if its relative or absolute path.
    If relative, make the conversion and return the path.
    If absolute, just return the path.
    '''
    path = urldefrag(path)[0]
    return urljoin(current_url, path)
    

def is_recursive_trap(parsed: ParseResult) -> bool:
    '''
    Given a parsed link check the path. If there are too many repeating directories 
    in the path returns True (is a trap) else False (not a trap)
    '''
    path_list = parsed.path.split("/")
    same_count = Counter(path_list)
    if same_count.most_common(1)[0][1] > 3:
        return True
    return False

def is_query_trap(parsed: ParseResult) -> bool:
    '''
    Given a parsed link check to make sure not stuck in a dynamic page by 
    checking to make sure the nuber or links geneated by queries from one page does not exceed REPEATED_THRESH
    returns true if trap else false
    '''
    global visit_count
    base = parsed.scheme + '://' + parsed.netloc + parsed.path
    if base not in visit_count:
        visit_count[base] = 0
    visit_count[base] = visit_count[base] + 1
    return visit_count[base] > REPEATED_THRESH

def subdomain_pages(urls: set) -> Counter[str, int]:
    '''
    Given a set of all urls visited populate a counter for number of urls visited
    for every subdomain in ics.uci.edu. 
    Return the subdomain_count Counter   
    '''
    subdomain_count = Counter()
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.endswith(".ics.uci.edu") and domain != "www.ics.uci.edu":
            subdomain_count[domain] += 1
    return subdomain_count

def summary() -> None:
    '''
    Prints out relvant information at the end of the crawl including: 
    150 most common words seen through out all pages 
    the largest page and its token count 
    the number of valid pages reached by the crawler 
    all the subdomains and their counts of ics.uci.edu
    '''
    max_tokens = [(k,v) for k, v in sorted(tokens.items(),key = lambda x: -1 * x[1]) if not re.match('^\d+$', k)]
    for token, freq in max_tokens[:150]:
        print(token, freq)
    print(largest_page +": ", largest_count)
    print('number of valid pages:', valid_page_count)
    subdomain_count = subdomain_pages(visited)
    print(sorted(subdomain_count.items()))

