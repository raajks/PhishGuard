"""
Feature extraction utilities for phishing detection
Extracts various features from URLs to help identify phishing attempts
Includes rule-based risk scoring and hybrid detection support
"""

import re
from urllib.parse import urlparse, urljoin
import ipaddress
import socket
from datetime import datetime
import json


# ============================================================
# KNOWN SAFE DOMAINS — Whitelist of trusted, popular domains
# ============================================================
KNOWN_SAFE_DOMAINS = {
    'google.com', 'www.google.com', 'mail.google.com', 'drive.google.com',
    'docs.google.com', 'maps.google.com', 'play.google.com',
    'github.com', 'www.github.com', 'api.github.com',
    'facebook.com', 'www.facebook.com', 'm.facebook.com',
    'twitter.com', 'www.twitter.com', 'x.com',
    'amazon.com', 'www.amazon.com', 'amazon.in',
    'microsoft.com', 'www.microsoft.com', 'outlook.com',
    'apple.com', 'www.apple.com',
    'wikipedia.org', 'en.wikipedia.org',
    'stackoverflow.com', 'www.stackoverflow.com',
    'linkedin.com', 'www.linkedin.com',
    'youtube.com', 'www.youtube.com',
    'instagram.com', 'www.instagram.com',
    'reddit.com', 'www.reddit.com',
    'netflix.com', 'www.netflix.com',
    'paypal.com', 'www.paypal.com',
    'dropbox.com', 'www.dropbox.com',
    'yahoo.com', 'www.yahoo.com',
    'bing.com', 'www.bing.com',
    'whatsapp.com', 'web.whatsapp.com',
    'zoom.us', 'slack.com', 'discord.com',
}


def extract_features(url):
    """
    Extract 30 features from a URL for machine learning model
    
    Features are designed to match UCI Phishing Dataset (30 features):
    Includes URL-based, domain-based, and protocol-based indicators
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary containing all extracted features
        list: List of 30 feature values in order for ML model
    """
    
    features = {}
    
    try:
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url_to_parse = 'http://' + url
        else:
            url_to_parse = url
        
        # Parse URL
        parsed = urlparse(url_to_parse)
        domain = parsed.netloc
        domain_part = domain.split(':')[0]
        
        # ===== Feature 1: Having IP Address =====
        has_ip = 0
        try:
            ipaddress.ip_address(domain_part)
            has_ip = -1  # Phishing indicator
        except ValueError:
            has_ip = 1  # Legitimate
        features['having_IP_Address'] = has_ip
        
        # ===== Feature 2: URL Length =====
        url_length = len(url)
        if url_length > 75:
            features['URL_length'] = -1
        elif url_length >= 54:
            features['URL_length'] = 0
        else:
            features['URL_length'] = 1
        
        # ===== Feature 3: Shortening Service =====
        shortening_services = ['bit.ly', 'tinyurl', 'ow.ly', 'short.link']
        features['Shortening_Service'] = -1 if any(s in domain_part for s in shortening_services) else 1
        
        # ===== Feature 4: Having @ Symbol =====
        features['having_At_Symbol'] = -1 if '@' in url else 1
        
        # ===== Feature 5: Double Slash Redirecting =====
        # Check for unusual double slashes after protocol
        features['double_slash_redirecting'] = -1 if '//' in url[8:] else 1
        
        # ===== Feature 6: Prefix-Suffix in Domain =====
        # Check for dash in domain (often used to trick users)
        features['Prefix_Suffix'] = -1 if '-' in domain_part else 1
        
        # ===== Feature 7: Having Sub Domains =====
        dot_count = domain_part.count('.')
        num_subdomains = max(0, dot_count - 1)
        if num_subdomains >= 3:
            features['having_Sub_Domain'] = -1
        elif num_subdomains == 2:
            features['having_Sub_Domain'] = 0
        else:
            features['having_Sub_Domain'] = 1
        
        # ===== Feature 8: SSL Final State (approximated) =====
        # Uses HTTPS as proxy for SSL - this is approximated
        if parsed.scheme == 'https':
            features['SSLFinal_State'] = 1  # Trusted (approximation)
        elif parsed.scheme == 'http':
            features['SSLFinal_State'] = -1  # Phishing (no SSL)
        else:
            features['SSLFinal_State'] = 0  # Unknown
        
        # ===== Feature 9: Domain Registration Length (approximated) =====
        # Approximated based on domain characteristics
        features['Domain_registration_length'] = 1  # Default to legitimate
        
        # ===== Feature 10: Favicon (approximated) =====
        features['Favicon'] = 1  # Default approximation
        
        # ===== Feature 11: Non-Standard Port =====
        port = parsed.port
        if port and port not in [80, 443, 8080, 8443]:
            features['NonStandard_Port'] = -1
        else:
            features['NonStandard_Port'] = 1
        
        # ===== Feature 12: HTTPS Domain URL =====
        if parsed.scheme == 'https':
            features['HTTPSDomainURL'] = 1
        else:
            features['HTTPSDomainURL'] = -1
        
        # ===== Feature 13: Request URL (approximated) =====
        features['RequestURL'] = 1  # Default approximation
        
        # ===== Feature 14: Anchor URL (approximated) =====
        features['AnchorURL'] = 1  # Default approximation
        
        # ===== Feature 15: Links in Script Tags (approximated) =====
        features['LinksInScriptTags'] = 1  # Default approximation
        
        # ===== Feature 16: Server Form Handler (approximated) =====
        features['ServerFormHandler'] = 1  # Default approximation
        
        # ===== Feature 17: Abnormal URL =====
        abnormal_keywords = ['login', 'verify', 'account', 'update', 'confirm', 'signin', 'signin.php', 'login.php']
        features['AbnormalURL'] = -1 if any(keyword in url.lower() for keyword in abnormal_keywords) else 1
        
        # ===== Feature 18: Website Forwarding (approximated) =====
        # Check for suspicious redirects
        features['Websitee_Forwarding'] = 1  # Default approximation
        
        # ===== Feature 19: Status Bar Customization (approximated) =====
        features['StatusBarCust'] = 1  # Default approximation
        
        # ===== Feature 20: Disabling Right Click (approximated) =====
        features['Disabling_Right_Click'] = 1  # Default approximation
        
        # ===== Feature 21: Using PopUp Window (approximated) =====
        features['using_PopUp_Window'] = 1  # Default approximation
        
        # ===== Feature 22: IFrame Redirection (approximated) =====
        features['IFrameRedirection'] = 1  # Default approximation
        
        # ===== Feature 23: Mismatched Domain (approximated) =====
        features['Mismatched_Domain'] = 1  # Default approximation
        
        # ===== Feature 24: Fake Favicon (approximated) =====
        features['Fake_favicon'] = 1  # Default approximation
        
        # ===== Feature 25: Domain in Title (approximated) =====
        # Check if domain appears in URL path (common in legitimate sites)
        features['Domain_in_Title'] = 1 if domain_part in parsed.path.lower() else -1
        
        # ===== Feature 26: WHOIS Known By (approximated) =====
        features['WHOIS_known_by'] = 1  # Default approximation
        
        # ===== Feature 27: Google Index (approximated) =====
        features['Google_Index'] = 1  # Default approximation
        
        # ===== Feature 28: Links in Comments (approximated) =====
        features['Links_in_comments'] = 1  # Default approximation
        
        # ===== Feature 29: SFH (Server Form Handler) =====
        features['SFH'] = 1  # Default approximation
        
        # ===== Feature 30: Abnormal URL (duplicate check) =====
        features['Abnormal_URL'] = features['AbnormalURL']
        
        # Prepare feature list for ML model (in consistent order)
        feature_list = [
            features['having_IP_Address'],
            features['URL_length'],
            features['Shortening_Service'],
            features['having_At_Symbol'],
            features['double_slash_redirecting'],
            features['Prefix_Suffix'],
            features['having_Sub_Domain'],
            features['SSLFinal_State'],
            features['Domain_registration_length'],
            features['Favicon'],
            features['NonStandard_Port'],
            features['HTTPSDomainURL'],
            features['RequestURL'],
            features['AnchorURL'],
            features['LinksInScriptTags'],
            features['ServerFormHandler'],
            features['AbnormalURL'],
            features['Websitee_Forwarding'],
            features['StatusBarCust'],
            features['Disabling_Right_Click'],
            features['using_PopUp_Window'],
            features['IFrameRedirection'],
            features['Mismatched_Domain'],
            features['Fake_favicon'],
            features['Domain_in_Title'],
            features['WHOIS_known_by'],
            features['Google_Index'],
            features['Links_in_comments'],
            features['SFH'],
            features['Abnormal_URL']
        ]
        
        return features, feature_list
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return default 30 features if parsing fails
        default_list = [1] * 30  # Default to legitimate for all features
        default_features = {f'feature_{i}': default_list[i] for i in range(30)}
        return default_features, default_list


# ============================================================
# RULE-BASED RISK SCORING — Independent of ML model
# ============================================================
def rule_based_check(url, features_dict):
    """
    Rule-based risk analysis that complements the ML model.
    Assigns risk scores (0-100) based on URL characteristics.
    
    Args:
        url (str): The URL being analyzed
        features_dict (dict): Extracted features from extract_features()
        
    Returns:
        dict: {
            'risk_score': int (0-100),
            'reasons': list of dicts with reason details,
            'has_ip': bool,
            'has_https': bool,
            'has_suspicious_keywords': bool
        }
    """
    risk_score = 0
    reasons = []
    
    # Normalize URL for analysis
    url_lower = url.lower()
    
    # Parse URL components
    if not url_lower.startswith(('http://', 'https://')):
        url_to_parse = 'http://' + url_lower
    else:
        url_to_parse = url_lower
    
    parsed = urlparse(url_to_parse)
    domain = parsed.netloc.split(':')[0]
    
    # --- Check 1: Known safe domain (early exit with bonus) ---
    is_whitelisted = domain in KNOWN_SAFE_DOMAINS
    if is_whitelisted:
        reasons.append({
            'type': 'safe',
            'icon': 'fa-circle-check',
            'text': f'Trusted domain: {domain} is a known legitimate website',
            'score_impact': -30
        })
        risk_score -= 30  # Bonus for trusted domains
    
    # --- Check 2: IP address instead of domain (+30 risk) ---
    has_ip = features_dict.get('having_IP_Address', 1) == -1
    if has_ip:
        risk_score += 30
        reasons.append({
            'type': 'danger',
            'icon': 'fa-network-wired',
            'text': 'URL uses an IP address instead of a domain name — common phishing tactic',
            'score_impact': 30
        })
    else:
        reasons.append({
            'type': 'safe',
            'icon': 'fa-globe',
            'text': 'URL uses a proper domain name',
            'score_impact': 0
        })
    
    # --- Check 3: Missing HTTPS (+20 risk) ---
    has_https = parsed.scheme == 'https'
    if not has_https:
        risk_score += 20
        reasons.append({
            'type': 'danger',
            'icon': 'fa-lock-open',
            'text': 'Connection is not secure (no HTTPS) — data can be intercepted',
            'score_impact': 20
        })
    else:
        reasons.append({
            'type': 'safe',
            'icon': 'fa-lock',
            'text': 'Secure HTTPS connection with encryption',
            'score_impact': 0
        })
    
    # --- Check 4: Suspicious keywords (+20 risk) ---
    suspicious_keywords = ['login', 'verify', 'account', 'update', 'confirm',
                           'signin', 'secure', 'banking', 'password', 'credential']
    found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
    has_suspicious_keywords = len(found_keywords) > 0
    
    if has_suspicious_keywords:
        risk_score += 20
        reasons.append({
            'type': 'warning',
            'icon': 'fa-comment-dots',
            'text': f'Suspicious keywords detected: {", ".join(found_keywords)}',
            'score_impact': 20
        })
    else:
        reasons.append({
            'type': 'safe',
            'icon': 'fa-comment-check',
            'text': 'No suspicious keywords found in URL',
            'score_impact': 0
        })
    
    # --- Check 5: URL length > 75 (+10 risk) ---
    if len(url) > 75:
        risk_score += 10
        reasons.append({
            'type': 'warning',
            'icon': 'fa-ruler',
            'text': f'URL is unusually long ({len(url)} characters) — may hide malicious content',
            'score_impact': 10
        })
    
    # --- Check 6: Dash in domain (+10 risk) ---
    if '-' in domain:
        risk_score += 10
        reasons.append({
            'type': 'warning',
            'icon': 'fa-minus',
            'text': f'Domain contains hyphens ({domain}) — often used to mimic real sites',
            'score_impact': 10
        })
    
    # --- Check 7: Suspicious TLD (+10 risk) ---
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.buzz', '.club', '.work']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        risk_score += 10
        reasons.append({
            'type': 'warning',
            'icon': 'fa-earth-americas',
            'text': 'Uses a suspicious top-level domain often associated with phishing',
            'score_impact': 10
        })
    
    # --- Check 8: @ symbol in URL (+15 risk) ---
    if '@' in url:
        risk_score += 15
        reasons.append({
            'type': 'danger',
            'icon': 'fa-at',
            'text': 'URL contains @ symbol — can redirect to a different domain',
            'score_impact': 15
        })
    
    # --- Check 9: URL shortener (+10 risk) ---
    shorteners = ['bit.ly', 'tinyurl.com', 'ow.ly', 't.co', 'goo.gl', 'short.link']
    if any(s in domain for s in shorteners):
        risk_score += 10
        reasons.append({
            'type': 'warning',
            'icon': 'fa-compress',
            'text': 'URL uses a shortening service — destination is hidden',
            'score_impact': 10
        })
    
    # --- Check 10: Multiple subdomains (+10 risk) ---
    subdomain_count = domain.count('.') - 1
    if subdomain_count >= 3:
        risk_score += 10
        reasons.append({
            'type': 'warning',
            'icon': 'fa-sitemap',
            'text': f'Excessive subdomains ({subdomain_count}) — unusual for legitimate sites',
            'score_impact': 10
        })
    
    # Clamp score between 0 and 100
    risk_score = max(0, min(100, risk_score))
    
    return {
        'risk_score': risk_score,
        'reasons': reasons,
        'has_ip': has_ip,
        'has_https': has_https,
        'has_suspicious_keywords': has_suspicious_keywords,
        'is_whitelisted': is_whitelisted
    }


# ============================================================
# HYBRID SCORING — Combines ML + Rule-based (70/30 weight)
# ============================================================
def compute_hybrid_score(ml_phishing_probability, rule_risk_score):
    """
    Combines ML model probability with rule-based risk score.
    
    Formula: final_score = (ml_score * 0.7) + (rule_score * 0.3)
    
    Args:
        ml_phishing_probability (float): ML model's phishing probability (0-100)
        rule_risk_score (int): Rule-based risk score (0-100)
        
    Returns:
        dict: {
            'final_score': float,
            'ml_contribution': float,
            'rule_contribution': float,
            'label': str ('Safe' / 'Suspicious' / 'Phishing')
        }
    """
    ml_contribution = ml_phishing_probability * 0.7
    rule_contribution = rule_risk_score * 0.3
    final_score = ml_contribution + rule_contribution
    
    # Clamp between 0 and 100
    final_score = max(0, min(100, final_score))
    
    # Smart decision logic based on final score thresholds
    if final_score < 20:
        label = 'Safe'
    elif final_score <= 50:
        label = 'Suspicious'
    else:
        label = 'Phishing'
    
    return {
        'final_score': round(final_score, 2),
        'ml_contribution': round(ml_contribution, 2),
        'rule_contribution': round(rule_contribution, 2),
        'label': label
    }


# ============================================================
# OVERRIDE RULES — Special forced labels for obvious cases
# ============================================================
def apply_override_rules(url, rule_result, hybrid_result):
    """
    Apply special override rules that force a label regardless of score.
    
    Override 1: IP address in URL → force at least "Suspicious"
    Override 2: No HTTPS + contains "login" → force "Phishing"
    Override 3: Known safe domain → force "Safe"
    
    Args:
        url (str): The URL being analyzed
        rule_result (dict): Output from rule_based_check()
        hybrid_result (dict): Output from compute_hybrid_score()
        
    Returns:
        dict: Updated hybrid_result with possible overrides applied
    """
    result = hybrid_result.copy()
    override_reason = None
    
    # Override 3: Known safe domain → force Safe
    if rule_result.get('is_whitelisted', False):
        result['label'] = 'Safe'
        result['final_score'] = min(result['final_score'], 10)
        override_reason = 'Known trusted domain — forced Safe'
    
    # Override 1: IP address → force Suspicious (highest priority after whitelist)
    elif rule_result.get('has_ip', False):
        result['label'] = 'Suspicious'
        result['final_score'] = max(result['final_score'], 35)
        override_reason = 'IP address detected — forced Suspicious'
    
    # Override 2: No HTTPS + login keyword → force Phishing (skip if IP-based)
    elif not rule_result.get('has_https', True):
        url_lower = url.lower()
        if 'login' in url_lower or 'signin' in url_lower:
            result['label'] = 'Phishing'
            result['final_score'] = max(result['final_score'], 75)
            override_reason = 'No HTTPS with login keyword — forced Phishing'
    
    result['override_applied'] = override_reason
    return result


def is_valid_url(url):
    """
    Validate URL format — rejects garbage like 'httpfree', requires a dot or valid IP.
    
    Args:
        url (str): URL to validate
        
    Returns:
        bool: True if URL appears valid, False otherwise
    """
    if not url or len(url.strip()) < 3 or len(url) > 2048:
        return False
    
    # Strip and normalise
    url = url.strip()
    
    # Must contain at least one dot (domain.tld) OR be an IP address
    # This catches garbage like "httpfree", "abcxyz", etc.
    stripped = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]  # get host part
    if '.' not in stripped:
        return False
    
    # Try matching as IP-based URL
    ip_pattern = re.compile(
        r'^(?:https?://)?'                      # optional scheme
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'  # IPv4
        r'(?::\d{1,5})?'                         # optional port
        r'(?:/.*)?$',
        re.IGNORECASE
    )
    if ip_pattern.match(url):
        return True
    
    # Match domain-based URL
    domain_pattern = re.compile(
        r'^(?:https?://)?'                       # optional scheme
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' # subdomains + domain
        r'[a-zA-Z]{2,}'                          # TLD (must be letters, min 2)
        r'(?::\d{1,5})?'                         # optional port
        r'(?:/.*)?$',                             # optional path
        re.IGNORECASE
    )
    return bool(domain_pattern.match(url))


def extract_ip_address(domain):
    """
    Extract IP address from domain
    
    Args:
        domain (str): Domain name to resolve
        
    Returns:
        str: IP address or None if unable to resolve
    """
    try:
        if is_valid_ip(domain):
            return domain
        
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None


def is_valid_ip(address):
    """
    Check if address is a valid IP
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def extract_domain_info(url):
    """
    Extract detailed domain information from URL
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary containing domain information
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]  # Remove port
        
        # Extract TLD
        parts = domain.split('.')
        tld = parts[-1] if len(parts) > 1 else 'unknown'
        
        # Extract main domain
        main_domain = '.'.join(parts[-2:]) if len(parts) > 1 else domain
        
        # Get IP address
        ip_address = extract_ip_address(domain)
        
        return {
            'domain': domain,
            'main_domain': main_domain,
            'tld': tld,
            'ip_address': ip_address or 'N/A',
            'protocol': parsed.scheme or 'http',
            'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
            'path': parsed.path or '/',
            'query': parsed.query or ''
        }
    except Exception as e:
        print(f"Error extracting domain info: {e}")
        return {
            'domain': 'Unknown',
            'main_domain': 'Unknown',
            'tld': 'Unknown',
            'ip_address': 'N/A',
            'protocol': 'Unknown',
            'port': 'Unknown',
            'path': '/',
            'query': ''
        }


def get_brand_info(domain):
    """
    Get brand information from domain
    
    Args:
        domain (str): Domain to check
        
    Returns:
        dict: Brand information
    """
    # Dictionary of known brands (simplified)
    brands = {
        'google': 'Google',
        'facebook': 'Facebook',
        'twitter': 'Twitter',
        'amazon': 'Amazon',
        'apple': 'Apple',
        'microsoft': 'Microsoft',
        'github': 'GitHub',
        'stackoverflow': 'Stack Overflow',
        'linkedin': 'LinkedIn',
        'paypal': 'PayPal',
        'dropbox': 'Dropbox',
        'netflix': 'Netflix',
        'instagram': 'Instagram',
        'youtube': 'YouTube',
        'reddit': 'Reddit'
    }
    
    domain_lower = domain.lower()
    
    for keyword, brand in brands.items():
        if keyword in domain_lower:
            return {
                'name': brand,
                'detected': True,
                'likelihood': 'High' if keyword == domain_lower.split('.')[0] else 'Medium'
            }
    
    return {
        'name': 'Unknown',
        'detected': False,
        'likelihood': 'None'
    }


def get_hosting_provider(ip_address):
    """
    Get hosting provider information from IP
    
    Args:
        ip_address (str): IP address
        
    Returns:
        dict: Hosting provider info
    """
    # Simplified hosting provider detection
    if not ip_address or ip_address == 'N/A':
        return {'name': 'Unknown', 'type': 'Unknown'}
    
    hosting_providers = {
        'google': ['142.251', '172.217', '172.218', '172.219'],
        'amazon': ['52.', '54.'],
        'cloudflare': ['104.16', '104.17', '104.18'],
        'microsoft': ['13.', '40.', '52.'],
        'facebook': ['31.13', '66.220'],
        'digitalocean': ['167.99', '188.166'],
        'linode': ['45.33', '96.126'],
        'heroku': ['50.19', '54.']
    }
    
    for provider, ip_prefixes in hosting_providers.items():
        for prefix in ip_prefixes:
            if ip_address.startswith(prefix):
                return {
                    'name': provider.title(),
                    'type': 'Cloud Hosting' if provider != 'unknown' else 'Unknown'
                }
    
    return {
        'name': 'Unknown Provider',
        'type': 'Shared Hosting'
    }


def get_location_from_ip(ip_address):
    """
    Get geolocation from IP (simplified)
    
    Args:
        ip_address (str): IP address
        
    Returns:
        dict: Location information
    """
    if not ip_address or ip_address == 'N/A':
        return {'country': 'Unknown', 'city': 'Unknown'}
    
    # Simplified geolocation based on IP ranges
    location_map = {
        '142.251': 'United States of America',  # Google
        '172.217': 'United States of America',  # Google
        '8.8.8.8': 'United States of America',  # Google DNS
        '1.1.1.1': 'United States of America',  # Cloudflare
    }
    
    for ip_prefix, country in location_map.items():
        if ip_address.startswith(ip_prefix):
            return {'country': country, 'city': 'N/A', 'coordinates': {'lat': 0, 'lng': 0}}
    
    return {
        'country': 'Unknown',
        'city': 'Unknown',
        'coordinates': {'lat': 0, 'lng': 0}
    }


def get_certificate_info(domain):
    """
    Get SSL certificate information (simplified)
    
    Args:
        domain (str): Domain to check
        
    Returns:
        dict: Certificate information
    """
    # This is simplified - in production, you'd use ssl module
    return {
        'issued_by': 'Unknown CA',
        'issued_to': domain,
        'valid': True,
        'expiry_date': 'N/A',
        'is_trusted': True
    }


def scan_threats(domain):
    """
    Scan for threats (simplified)
    
    Args:
        domain (str): Domain to scan
        
    Returns:
        dict: Threat information
    """
    return {
        'past_phish_on_host': 0,
        'past_phish_on_ip': 0,
        'phishing_kits': 0,
        'malware_detected': False,
        'spam_reports': 0
    }


def generate_explanation(features, url, prediction, confidence, rule_reasons=None):
    """
    Generate human-readable explanations for the scan result.
    Combines ML feature analysis with rule-based reasons.
    
    Args:
        features (dict): Extracted features from the URL (UCI format: 1=safe, -1=phishing)
        url (str): The analyzed URL
        prediction (str): "Safe" / "Suspicious" / "Phishing"
        confidence (float): Final hybrid confidence score (0-100)
        rule_reasons (list): List of reason dicts from rule_based_check()
        
    Returns:
        dict: Contains danger_reasons, safe_reasons, and summary
    """
    danger_reasons = []
    safe_reasons = []
    
    # --- Analyze ML features (UCI convention: 1=safe, -1=phishing, 0=suspicious) ---
    
    feature_explanations = {
        'having_IP_Address': {
            -1: {'reason': 'Direct IP Address Used', 'explanation': 'URL uses an IP address instead of a domain name. Phishing sites often use IPs to avoid domain reputation checks.', 'severity': 'high'},
            1: {'reason': 'Uses Domain Name', 'explanation': 'URL uses a proper domain name instead of an IP address.', 'severity': 'safe'}
        },
        'URL_length': {
            -1: {'reason': 'Very Long URL', 'explanation': 'URL is unusually long (>75 chars). Attackers use long URLs to hide suspicious parts.', 'severity': 'medium'},
            1: {'reason': 'Normal URL Length', 'explanation': 'URL length is within a safe range for legitimate websites.', 'severity': 'safe'}
        },
        'Shortening_Service': {
            -1: {'reason': 'URL Shortener Detected', 'explanation': 'URL uses a shortening service which hides the real destination.', 'severity': 'medium'},
            1: {'reason': 'No URL Shortener', 'explanation': 'URL does not use a shortening service.', 'severity': 'safe'}
        },
        'having_At_Symbol': {
            -1: {'reason': '@ Symbol Found', 'explanation': 'URL contains @ symbol, which can redirect users to a different domain while displaying a trusted one.', 'severity': 'high'},
            1: {'reason': 'No @ Symbol', 'explanation': 'URL does not contain suspicious @ symbol.', 'severity': 'safe'}
        },
        'Prefix_Suffix': {
            -1: {'reason': 'Dashes in Domain', 'explanation': 'Domain contains hyphens (e.g., "g-oogle.com"). Attackers use this to mimic legitimate domains.', 'severity': 'medium'},
            1: {'reason': 'Clean Domain Name', 'explanation': 'Domain has no suspicious hyphens.', 'severity': 'safe'}
        },
        'SSLFinal_State': {
            -1: {'reason': 'No HTTPS/SSL', 'explanation': 'Website does not use HTTPS encryption. Your data could be intercepted.', 'severity': 'high'},
            1: {'reason': 'HTTPS Encryption Active', 'explanation': 'Website uses secure HTTPS protocol with SSL/TLS encryption.', 'severity': 'safe'}
        },
        'AbnormalURL': {
            -1: {'reason': 'Suspicious Keywords in URL', 'explanation': 'URL contains phishing keywords like "login", "verify", "account", "update".', 'severity': 'medium'},
            1: {'reason': 'No Suspicious Keywords', 'explanation': 'URL does not contain common phishing-related keywords.', 'severity': 'safe'}
        },
        'having_Sub_Domain': {
            -1: {'reason': 'Multiple Subdomains', 'explanation': 'URL has many subdomains which is unusual for legitimate sites.', 'severity': 'medium'},
            1: {'reason': 'Clean Subdomain Structure', 'explanation': 'URL has a normal domain structure.', 'severity': 'safe'}
        },
        'NonStandard_Port': {
            -1: {'reason': 'Non-Standard Port', 'explanation': 'URL uses an unusual port number not typical for web traffic.', 'severity': 'medium'},
            1: {'reason': 'Standard Port', 'explanation': 'URL uses a standard web port (80/443).', 'severity': 'safe'}
        },
        'HTTPSDomainURL': {
            -1: {'reason': 'HTTP Only (Not Secure)', 'explanation': 'Website uses plain HTTP without encryption.', 'severity': 'high'},
            1: {'reason': 'HTTPS Domain', 'explanation': 'Domain uses HTTPS protocol.', 'severity': 'safe'}
        }
    }
    
    # Process each feature
    for feature_key, explanations in feature_explanations.items():
        value = features.get(feature_key)
        if value is not None and value in explanations:
            info = explanations[value]
            entry = {
                'reason': f"{'⚠️' if info['severity'] != 'safe' else '✓'} {info['reason']}",
                'explanation': info['explanation'],
                'severity': info['severity'],
                'icon': '🚨' if info['severity'] == 'high' else ('⚠️' if info['severity'] == 'medium' else '✅')
            }
            if info['severity'] == 'safe':
                safe_reasons.append(entry)
            else:
                danger_reasons.append(entry)
    
    # --- Add rule-based reasons if provided ---
    if rule_reasons:
        for r in rule_reasons:
            if r['type'] == 'danger':
                danger_reasons.append({
                    'reason': f"🚨 {r['text']}",
                    'explanation': r['text'],
                    'severity': 'high',
                    'icon': '🚨'
                })
            elif r['type'] == 'warning':
                danger_reasons.append({
                    'reason': f"⚠️ {r['text']}",
                    'explanation': r['text'],
                    'severity': 'medium',
                    'icon': '⚠️'
                })
            elif r['type'] == 'safe':
                safe_reasons.append({
                    'reason': f"✓ {r['text']}",
                    'explanation': r['text'],
                    'severity': 'safe',
                    'icon': '✅'
                })
    
    # Deduplicate reasons by checking for similar text
    seen_danger = set()
    unique_danger = []
    for r in danger_reasons:
        key = r['explanation'][:40]
        if key not in seen_danger:
            seen_danger.add(key)
            unique_danger.append(r)
    danger_reasons = unique_danger
    
    seen_safe = set()
    unique_safe = []
    for r in safe_reasons:
        key = r['explanation'][:40]
        if key not in seen_safe:
            seen_safe.add(key)
            unique_safe.append(r)
    safe_reasons = unique_safe
    
    # Generate summary
    if prediction == 'Phishing':
        summary = f"🚨 HIGH RISK — {len(danger_reasons)} warning signs detected. This URL shows strong phishing characteristics."
    elif prediction == 'Suspicious':
        summary = f"⚠️ CAUTION — {len(danger_reasons)} warning signs found. This URL has some suspicious characteristics."
    else:
        summary = f"✅ SAFE — {len(safe_reasons)} positive indicators confirmed. This URL appears legitimate."
    
    return {
        'summary': summary,
        'danger_reasons': danger_reasons,
        'safe_reasons': safe_reasons,
        'total_warnings': len(danger_reasons),
        'total_safe_indicators': len(safe_reasons)
    }


