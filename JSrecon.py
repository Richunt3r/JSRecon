#!/usr/bin/env python3
"""
JavaScript Reconnaissance Tool
Discovers, validates, and analyzes JavaScript files across domains and subdomains

Author: VIVEK GOSWAMI
LinkedIn: https://www.linkedin.com/in/vivekgoswamii
GitHub: Follow for more security tools and updates

Description:
A powerful reconnaissance tool that discovers, validates, and analyzes JavaScript 
files across domains and subdomains with advanced crawling capabilities and path 
disclosure detection.
"""

import requests
import argparse
import re
import sys
import json
from urllib.parse import urljoin, urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class JSRecon:
    def __init__(self, target, threads=10, timeout=10, output_dir="js_recon_output"):
        self.target = self.normalize_url(target)
        self.domain = urlparse(self.target).netloc
        self.threads = threads
        self.timeout = timeout
        self.output_dir = output_dir
        
        # Storage
        self.discovered_js = set()
        self.validated_js = {}
        self.subdomains = set()
        self.crawled_urls = set()
        self.path_disclosures = []
        
        # Session with retry strategy
        self.session = self.create_session()
        
        print(f"{Colors.BOLD}{Colors.CYAN}╔════════════════════════════════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}║     JavaScript Reconnaissance Tool v1.0                        ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}║     Author: VIVEK GOSWAMI                                      ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}║     LinkedIn: https://www.linkedin.com/in/vivekgoswamii        ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}╚════════════════════════════════════════════════════════════════╝{Colors.END}")
        print(f"\n{Colors.GREEN}[+] Target: {self.target}{Colors.END}")
        print(f"{Colors.GREEN}[+] Threads: {self.threads}{Colors.END}\n")

    def normalize_url(self, url):
        """Ensure URL has proper scheme"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def create_session(self):
        """Create requests session with retry strategy"""
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return session

    def fetch_url(self, url, verify_ssl=False):
        """Fetch URL with error handling"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=verify_ssl, allow_redirects=True)
            return response
        except requests.exceptions.RequestException:
            return None

    def is_same_domain(self, url):
        """Check if URL belongs to target domain or subdomain"""
        parsed = urlparse(url)
        return parsed.netloc.endswith(self.domain) or parsed.netloc == self.domain

    def extract_js_from_html(self, html_content, base_url):
        """Extract JavaScript file references from HTML"""
        js_files = set()
        
        # Script src attributes
        script_pattern = r'<script[^>]+src=["\'](.*?)["\']'
        for match in re.finditer(script_pattern, html_content, re.IGNORECASE):
            js_url = match.group(1)
            full_url = urljoin(base_url, js_url)
            if self.is_js_file(full_url):
                js_files.add(full_url)
        
        # JavaScript files in various attributes
        patterns = [
            r'["\'](https?://[^"\']*\.js(?:\?[^"\']*)?)["\']',
            r'["\']([/][^"\']*\.js(?:\?[^"\']*)?)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html_content):
                js_url = match.group(1)
                full_url = urljoin(base_url, js_url)
                if self.is_js_file(full_url):
                    js_files.add(full_url)
        
        return js_files

    def is_js_file(self, url):
        """Check if URL points to a JavaScript file"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return (path.endswith('.js') or 
                path.endswith('.min.js') or 
                path.endswith('.mjs') or
                'javascript' in parsed.path.lower())

    def extract_links_from_html(self, html_content, base_url):
        """Extract all links from HTML for crawling"""
        links = set()
        
        # href attributes
        href_pattern = r'href=["\'](.*?)["\']'
        for match in re.finditer(href_pattern, html_content, re.IGNORECASE):
            link = match.group(1)
            full_url = urljoin(base_url, link)
            if self.is_same_domain(full_url):
                links.add(full_url)
        
        return links

    def extract_subdomains(self, content):
        """Extract subdomain references from content"""
        subdomain_pattern = rf'([a-zA-Z0-9][-a-zA-Z0-9]*\.)*{re.escape(self.domain)}'
        matches = re.finditer(subdomain_pattern, content)
        
        for match in matches:
            subdomain = match.group(0)
            if subdomain not in self.subdomains:
                self.subdomains.add(subdomain)

    def analyze_js_content(self, js_url, content):
        """Analyze JavaScript content for path disclosures"""
        disclosures = []
        
        # Patterns for path disclosure
        path_patterns = [
            r'["\'](/[a-zA-Z0-9_\-/\.]+\.(php|asp|aspx|jsp|do|action|cgi))["\']',
            r'["\'](/api/[a-zA-Z0-9_\-/\.]+)["\']',
            r'["\'](/admin[a-zA-Z0-9_\-/\.]*)["\']',
            r'["\'](/config[a-zA-Z0-9_\-/\.]*)["\']',
            r'["\'](/backup[a-zA-Z0-9_\-/\.]*)["\']',
            r'["\'](/upload[a-zA-Z0-9_\-/\.]*)["\']',
            r'["\'](/download[a-zA-Z0-9_\-/\.]*)["\']',
            r'path["\s:=]+["\'](/[a-zA-Z0-9_\-/\.]+)["\']',
            r'endpoint["\s:=]+["\'](/[a-zA-Z0-9_\-/\.]+)["\']',
            r'url["\s:=]+["\'](/[a-zA-Z0-9_\-/\.]+)["\']',
        ]
        
        for pattern in path_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                path = match.group(1)
                if len(path) > 3:  # Minimum path length
                    disclosures.append(path)
        
        # Extract AWS S3 buckets
        s3_pattern = r'([a-zA-Z0-9.\-]+\.s3[a-zA-Z0-9.\-]*\.amazonaws\.com)'
        s3_matches = re.finditer(s3_pattern, content)
        for match in s3_matches:
            disclosures.append(f"S3_BUCKET: {match.group(1)}")
        
        # Extract API keys patterns (basic)
        api_patterns = [
            r'api[_-]?key["\s:=]+["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'apikey["\s:=]+["\']([a-zA-Z0-9_\-]{20,})["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                disclosures.append(f"POTENTIAL_API_KEY: {match.group(1)[:20]}...")
        
        if disclosures:
            unique_disclosures = list(set(disclosures))
            self.path_disclosures.append({
                'js_url': js_url,
                'disclosures': unique_disclosures
            })
        
        # Extract more subdomains from JS
        self.extract_subdomains(content)

    def validate_js_file(self, js_url):
        """Validate JS file and return status code"""
        try:
            response = self.fetch_url(js_url, verify_ssl=False)
            if response and response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                # Verify it's actually JavaScript
                if ('javascript' in content_type or 
                    'application/json' in content_type or
                    self.is_js_file(js_url)):
                    return {
                        'url': js_url,
                        'status': 200,
                        'size': len(response.content),
                        'content': response.text
                    }
        except Exception:
            pass
        return None

    def crawl_url(self, url):
        """Crawl a single URL to discover JS files and links"""
        if url in self.crawled_urls:
            return set(), set()
        
        self.crawled_urls.add(url)
        js_files = set()
        new_links = set()
        
        try:
            response = self.fetch_url(url, verify_ssl=False)
            if response and response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                
                if 'text/html' in content_type:
                    # Extract JS files
                    js_files = self.extract_js_from_html(response.text, url)
                    # Extract links for further crawling
                    new_links = self.extract_links_from_html(response.text, url)
                    # Extract subdomains
                    self.extract_subdomains(response.text)
                    
        except Exception as e:
            pass
        
        return js_files, new_links

    def crawl_site(self, max_depth=3):
        """Crawl the site to discover JS files"""
        print(f"{Colors.YELLOW}[*] Starting crawling (max depth: {max_depth})...{Colors.END}")
        
        to_crawl = {self.target}
        depth = 0
        
        while to_crawl and depth < max_depth:
            print(f"{Colors.CYAN}[*] Crawling depth {depth + 1}: {len(to_crawl)} URLs{Colors.END}")
            
            new_js_files = set()
            next_level = set()
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {executor.submit(self.crawl_url, url): url for url in to_crawl}
                
                for future in as_completed(future_to_url):
                    js_files, links = future.result()
                    new_js_files.update(js_files)
                    next_level.update(links - self.crawled_urls)
            
            self.discovered_js.update(new_js_files)
            print(f"{Colors.GREEN}[+] Found {len(new_js_files)} JS files at depth {depth + 1}{Colors.END}")
            
            to_crawl = next_level
            depth += 1
        
        print(f"{Colors.GREEN}[+] Crawling complete! Total URLs crawled: {len(self.crawled_urls)}{Colors.END}")
        print(f"{Colors.GREEN}[+] Total JS files discovered: {len(self.discovered_js)}{Colors.END}")

    def enumerate_subdomains_from_js(self):
        """Check discovered subdomains"""
        if not self.subdomains:
            return
        
        print(f"\n{Colors.YELLOW}[*] Found {len(self.subdomains)} unique subdomains{Colors.END}")
        
        # Try to fetch from subdomains
        for subdomain in list(self.subdomains)[:20]:  # Limit to first 20
            for scheme in ['https', 'http']:
                url = f"{scheme}://{subdomain}"
                try:
                    response = self.fetch_url(url, verify_ssl=False)
                    if response and response.status_code == 200:
                        print(f"{Colors.GREEN}[+] Active subdomain: {url}{Colors.END}")
                        # Crawl this subdomain too
                        js_files, _ = self.crawl_url(url)
                        self.discovered_js.update(js_files)
                        break
                except Exception:
                    continue

    def validate_all_js(self):
        """Validate all discovered JS files (200 status only)"""
        print(f"\n{Colors.YELLOW}[*] Validating {len(self.discovered_js)} JS files...{Colors.END}")
        
        valid_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.validate_js_file, js_url): js_url 
                           for js_url in self.discovered_js}
            
            for future in as_completed(future_to_url):
                result = future.result()
                if result:
                    self.validated_js[result['url']] = result
                    valid_count += 1
                    print(f"{Colors.GREEN}[✓] {result['url']} ({result['size']} bytes){Colors.END}")
        
        print(f"\n{Colors.GREEN}[+] Validated {valid_count} JS files (200 status code){Colors.END}")

    def analyze_all_js(self):
        """Analyze all validated JS files for path disclosures"""
        print(f"\n{Colors.YELLOW}[*] Analyzing JS files for path disclosures...{Colors.END}")
        
        for js_url, js_data in self.validated_js.items():
            self.analyze_js_content(js_url, js_data['content'])
        
        print(f"{Colors.GREEN}[+] Analysis complete!{Colors.END}")
        if self.path_disclosures:
            print(f"{Colors.CYAN}[*] Found path disclosures in {len(self.path_disclosures)} files{Colors.END}")

    def save_results(self):
        """Save all results to files"""
        import os
        os.makedirs(self.output_dir, exist_ok=True)
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        base_name = f"{self.domain}_{timestamp}"
        
        # Save all discovered JS files
        all_js_file = f"{self.output_dir}/{base_name}_all_js.txt"
        with open(all_js_file, 'w') as f:
            for js_url in sorted(self.discovered_js):
                f.write(f"{js_url}\n")
        print(f"\n{Colors.GREEN}[+] All JS files saved to: {all_js_file}{Colors.END}")
        
        # Save validated JS files (200 status)
        validated_js_file = f"{self.output_dir}/{base_name}_validated_js.txt"
        with open(validated_js_file, 'w') as f:
            for js_url, data in sorted(self.validated_js.items()):
                f.write(f"{js_url} | Size: {data['size']} bytes | Status: {data['status']}\n")
        print(f"{Colors.GREEN}[+] Validated JS files (200 OK) saved to: {validated_js_file}{Colors.END}")
        
        # Save path disclosures
        if self.path_disclosures:
            disclosure_file = f"{self.output_dir}/{base_name}_path_disclosures.txt"
            with open(disclosure_file, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("PATH DISCLOSURES AND SENSITIVE INFORMATION\n")
                f.write("=" * 80 + "\n\n")
                
                for item in self.path_disclosures:
                    f.write(f"\n[JS FILE] {item['js_url']}\n")
                    f.write("-" * 80 + "\n")
                    for disclosure in item['disclosures']:
                        f.write(f"  └─ {disclosure}\n")
                    f.write("\n")
            
            print(f"{Colors.CYAN}[+] Path disclosures saved to: {disclosure_file}{Colors.END}")
        
        # Save JSON report
        json_file = f"{self.output_dir}/{base_name}_report.json"
        report = {
            'target': self.target,
            'timestamp': timestamp,
            'statistics': {
                'urls_crawled': len(self.crawled_urls),
                'js_files_discovered': len(self.discovered_js),
                'js_files_validated': len(self.validated_js),
                'subdomains_found': len(self.subdomains),
                'path_disclosures_found': len(self.path_disclosures)
            },
            'validated_js_files': list(self.validated_js.keys()),
            'subdomains': list(self.subdomains),
            'path_disclosures': self.path_disclosures
        }
        
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"{Colors.GREEN}[+] JSON report saved to: {json_file}{Colors.END}")
        
        # Save subdomains
        if self.subdomains:
            subdomain_file = f"{self.output_dir}/{base_name}_subdomains.txt"
            with open(subdomain_file, 'w') as f:
                for subdomain in sorted(self.subdomains):
                    f.write(f"{subdomain}\n")
            print(f"{Colors.GREEN}[+] Subdomains saved to: {subdomain_file}{Colors.END}")

    def print_summary(self):
        """Print summary statistics"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}RECONNAISSANCE SUMMARY{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.END}\n")
        
        print(f"{Colors.GREEN}Target:{Colors.END} {self.target}")
        print(f"{Colors.GREEN}URLs Crawled:{Colors.END} {len(self.crawled_urls)}")
        print(f"{Colors.GREEN}JS Files Discovered:{Colors.END} {len(self.discovered_js)}")
        print(f"{Colors.GREEN}JS Files Validated (200 OK):{Colors.END} {len(self.validated_js)}")
        print(f"{Colors.GREEN}Subdomains Found:{Colors.END} {len(self.subdomains)}")
        print(f"{Colors.GREEN}Files with Path Disclosures:{Colors.END} {len(self.path_disclosures)}")
        
        if self.path_disclosures:
            total_disclosures = sum(len(item['disclosures']) for item in self.path_disclosures)
            print(f"{Colors.YELLOW}Total Path Disclosures:{Colors.END} {total_disclosures}")
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.END}\n")

    def run(self, crawl_depth=3):
        """Main execution flow"""
        start_time = time.time()
        
        # Step 1: Crawl the site
        self.crawl_site(max_depth=crawl_depth)
        
        # Step 2: Enumerate subdomains
        self.enumerate_subdomains_from_js()
        
        # Step 3: Validate all JS files (only 200 status)
        self.validate_all_js()
        
        # Step 4: Analyze JS content
        self.analyze_all_js()
        
        # Step 5: Save results
        self.save_results()
        
        # Step 6: Print summary
        self.print_summary()
        
        elapsed_time = time.time() - start_time
        print(f"{Colors.GREEN}[+] Scan completed in {elapsed_time:.2f} seconds{Colors.END}\n")


def main():
    parser = argparse.ArgumentParser(
        description='JavaScript Reconnaissance Tool - Discover and analyze JS files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 js_recon.py -u example.com
  python3 js_recon.py -u https://example.com -t 20 -d 4
  python3 js_recon.py -u example.com -o custom_output
        '''
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL or domain')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Crawling depth (default: 3)')
    parser.add_argument('-o', '--output', default='js_recon_output', help='Output directory (default: js_recon_output)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    args = parser.parse_args()
    
    try:
        recon = JSRecon(
            target=args.url,
            threads=args.threads,
            timeout=args.timeout,
            output_dir=args.output
        )
        recon.run(crawl_depth=args.depth)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {str(e)}{Colors.END}")
        sys.exit(1)


if __name__ == "__main__":
    main()
