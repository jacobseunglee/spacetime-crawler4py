import re
from urllib.parse import urlparse, urldefrag
from bs4 import BeautifulSoup

REPEATED_TRESH = 15

visited = {}

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

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
        print(resp.error)
        return []
    
    parsed_html = BeautifulSoup(resp.raw_response.content, "lxml")
    # for link in parsed_html.find_all("a"):
    #     # get the link and convert
    #     check_link(link.get("href"))

    return [get_absolute_path(link.get("href"), resp.url) for link in parsed_html.find_all("a")]

def in_domain_scope(parsed):
    for domain in [".ics.uci.edu", ".cs.uci.edu", ".informatics.uci.edu", ".stat.uci.edu"]:
        if parsed.netloc.endswith(domain):
            return True
    return False

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.

    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        if not in_domain_scope(parsed):
            return False
        
        # disallowed robots.txt urls/paths
        # robotparse = robotparser.RobotFileParser(f"http://{host}:{port}/" + "?" + parsed.scheme + "://" + parsed.netloc + "/robots.txt")
        # robotparse.read()
        # if not robotparse.can_fetch("*", url):
        #     return False
        
        # if is_trap(url):
        #     return False

        # dirs = parsed.path.split("/")
        # if parsed.netloc == "www.ics.uci.edu":
        #     if dirs[1] in ["bin", "~mpufal"]:
        #         return False
        # elif parsed.netloc in ["www.stat.uci.edu", "www.cs.uci.edu"]:
        #     if dirs[1] == "wp-admin" and dirs[2] != "admin-ajax.php":
        #         return False
        # elif parsed.netloc == "www.informatics.uci.edu":
        #     if dirs[1] == "research" and dirs[2] not in \
        #         ["labs-centers", "areas-of-expertise", "example-research-projects", "phd-research",
        #          "past-dissertations", "masters-research", "undergraduate-research", "gifts-grants"]:
        #         return False
        #     elif dirs[1] == "wp-admin" and dirs[2] != "admin-ajax.php":
        #         return False
        # else:
        #     # if outside of the domains return False
        #     return False
        
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
    if base in visited:
        visited[base] += 1
        if visited[base] > REPEATED_TRESH:
            return True
        else:
            return False
    else:
        visited[base] = 1
        return True
    
