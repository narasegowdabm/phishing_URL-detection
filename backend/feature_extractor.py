# feature_extractor.py
import re
import math
import urllib.parse
import tldextract
import string

def is_ip(address):
    """Return True if the address is a valid IPv4 address."""
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(ipv4_pattern, address) is not None

def shannon_entropy(s):
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0
    probs = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    entropy = -sum(p * math.log(p, 2) for p in probs)
    return entropy

def extract_features(url):
    """
    Extract 80 features from a URL.
    The features below must be in the same order as used when training your model.
    """
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname if parsed.hostname else ""
    path = parsed.path if parsed.path else ""
    query = parsed.query if parsed.query else ""
    
    # Features 1-56
    f1 = len(url)                                # Full URL length
    f2 = len(hostname)                           # Hostname length
    f3 = 1 if is_ip(hostname) else 0             # Contains IP in hostname
    f4 = url.count('.')                          # Count of '.' in URL
    f5 = url.count('-')                          # Count of '-' in URL
    f6 = url.count('@')                          # Count of '@' in URL
    f7 = url.count('?')                          # Count of '?' in URL
    f8 = url.count('&')                          # Count of '&' in URL
    f9 = url.count('|')                          # Count of '|' in URL
    f10 = url.count('=')                         # Count of '=' in URL
    f11 = url.count('_')                         # Count of '_' in URL
    f12 = url.count('~')                         # Count of '~' in URL
    f13 = url.count('%')                         # Count of '%' in URL
    f14 = url.count('/')                         # Count of '/' in URL
    f15 = url.count('*')                         # Count of '*' in URL
    f16 = url.count(':')                         # Count of ':' in URL
    f17 = url.count(',')                         # Count of ',' in URL
    f18 = url.count(';')                         # Count of ';' in URL
    f19 = url.count('$')                         # Count of '$' in URL
    f20 = url.count(" ") + url.count("%20")       # Count of spaces and '%20'
    f21 = url.lower().count("www")               # Count of "www" in URL
    f22 = url.lower().count(".com")              # Count of ".com" in URL
    f23 = url.lower().count("http")              # Count of "http" in URL
    f24 = url.count("//")                        # Count of '//' in URL
    f25 = 1 if url.lower().startswith("https://") else 0  # HTTPS indicator
    f26 = sum(c.isdigit() for c in url) / len(url) if url else 0  # Ratio of digits in URL
    f27 = sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0  # Ratio of digits in hostname
    f28 = 1 if "xn--" in hostname else 0         # Punycode indicator
    f29 = 1 if parsed.port else 0                # Port indicator
    f30 = shannon_entropy(url)                   # Shannon entropy of full URL
    subdomains = hostname.split('.') if hostname else []
    f31 = len(subdomains) - 2 if len(subdomains) > 2 else 0  # Number of subdomains
    extracted = tldextract.extract(url)
    f32 = len(extracted.suffix)                  # TLD length
    f33 = hostname.count('-')                    # Count of '-' in hostname
    f34 = hostname.count('_')                    # Count of '_' in hostname
    f35 = sum(c.isdigit() for c in hostname)       # Count of digits in hostname (absolute)
    f36 = shannon_entropy(hostname)              # Shannon entropy of hostname
    f37 = len(path)                              # Length of path
    f38 = path.count('/')                        # Count of '/' in path
    f39 = len(query)                             # Length of query string
    f40 = len(query.split('&')) if query else 0  # Count of parameters in query string
    f41 = query.count('=') if query else 0       # Count of '=' in query string
    suspicious_words = ["login", "secure", "account", "update"]
    f42 = sum(url.lower().count(word) for word in suspicious_words)  # Count of suspicious words
    f43 = 1 if f23 > 1 else 0                      # Flag if multiple "http" occurrences
    alphabets = sum(c.isalpha() for c in url)
    f44 = alphabets / len(url) if url else 0       # Ratio of alphabet characters in URL
    f45 = sum(1 for c in url if c.isupper())        # Count of uppercase letters in URL
    f46 = sum(1 for c in url if c.islower())        # Count of lowercase letters in URL
    f47 = len(re.findall(r'[^a-zA-Z0-9\s]', url))  # Count of non-alphanumeric symbols in URL
    consonants = sum(1 for c in hostname.lower() if c in "bcdfghjklmnpqrstvwxyz")
    f48 = consonants / len(hostname) if hostname else 0  # Ratio of consonants in hostname
    f49 = sum(1 for c in hostname.lower() if c in "aeiou")  # Count of vowels in hostname
    f50 = f49 / len(hostname) if hostname else 0           # Ratio of vowels in hostname
    f51 = 1 if "www" in hostname.lower() else 0            # Flag: Contains "www" in hostname
    f52 = 1 if "https" in url.lower() else 0               # Flag: Contains "https" in URL
    f53 = sum(c.isdigit() for c in url)                    # Count of digits in URL (absolute)
    f54 = shannon_entropy(path)                           # Shannon entropy of path
    f55 = len(query) / len(url) if url else 0              # Ratio of query length to URL length
    f56 = sum(1 for c in url if c in string.punctuation)   # Count of punctuation characters in URL

    # Features 57-80 (Additional features)
    f57 = sum(c.isalpha() for c in url)                   # Count of alphabetic characters in URL (absolute)
    f58 = f57 / len(url) if url else 0                    # Ratio of alphabetic characters in URL
    f59 = url.count(' ')                                  # Count of whitespace characters in URL
    f60 = f59 / len(url) if url else 0                    # Ratio of whitespace characters in URL
    f61 = sum(1 for c in hostname if c in string.punctuation)  # Count of punctuation in hostname
    f62 = f61 / len(hostname) if hostname else 0          # Ratio of punctuation in hostname
    vowels_url = sum(1 for c in url.lower() if c in "aeiou")
    f63 = vowels_url                                     # Count of vowels in URL
    f64 = vowels_url / len(url) if url else 0             # Ratio of vowels in URL
    consonants_url = sum(1 for c in url.lower() if c in "bcdfghjklmnpqrstvwxyz")
    f65 = consonants_url                                 # Count of consonants in URL
    f66 = consonants_url / len(url) if url else 0          # Ratio of consonants in URL
    f67 = sum(c.isalpha() for c in hostname)             # Count of alphabetic characters in hostname
    f68 = f67 / len(hostname) if hostname else 0          # Ratio of alphabetic characters in hostname
    f69 = shannon_entropy(query)                         # Shannon entropy of query string
    f70 = len([c for c in query if not c.isalnum() and not c.isspace()])  # Count of special characters in query string
    f71 = f70 / len(query) if query else 0                # Ratio of special characters in query string
    segments = [seg for seg in path.split('/') if seg]
    f72 = len(segments)                                  # Count of segments in path
    f73 = sum(len(seg) for seg in segments) / len(segments) if segments else 0  # Average segment length
    f74 = max((len(seg) for seg in segments), default=0)  # Maximum segment length in path
    words = re.findall(r'\w+', url)
    f75 = len(words)                                     # Count of words in URL
    f76 = sum(c.isdigit() for c in query)                # Count of digits in query string
    f77 = sum(c.isalpha() for c in query)                # Count of alphabetic characters in query string
    f78 = f76 / len(query) if query else 0               # Ratio of digits in query string
    f79 = f77 / len(query) if query else 0               # Ratio of alphabetic characters in query string
    f80 = len(query) / len(hostname) if hostname else 0    # Ratio of query length to hostname length

    features = [
        f1, f2, f3, f4, f5, f6, f7, f8, f9, f10,
        f11, f12, f13, f14, f15, f16, f17, f18, f19, f20,
        f21, f22, f23, f24, f25, f26, f27, f28, f29, f30,
        f31, f32, f33, f34, f35, f36, f37, f38, f39, f40,
        f41, f42, f43, f44, f45, f46, f47, f48, f49, f50,
        f51, f52, f53, f54, f55, f56, f57, f58, f59, f60,
        f61, f62, f63, f64, f65, f66, f67, f68, f69, f70,
        f71, f72, f73, f74, f75, f76, f77, f78, f79, f80
    ]
    return features
