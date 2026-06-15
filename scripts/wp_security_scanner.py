#!/usr/bin/env python3
"""
WordPress Security Scanner - Educational Tool
For authorized security testing only.

DISCLAIMER: Only use this tool on systems you own or have explicit permission to test.
Unauthorized access to computer systems is illegal.
"""

import requests
import argparse
import sys
import time
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional
import re


class WordPressSecurityScanner:
    """WordPress security scanner for educational purposes."""
    
    def __init__(self, target_url: str, cookie: Optional[str] = None):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WordPress-Security-Scanner/1.0 (Educational)'
        })
        if cookie:
            self.session.headers['Cookie'] = cookie
        self.findings = []
        
    def log_finding(self, category: str, severity: str, description: str, 
                    evidence: str = "", remediation: str = ""):
        """Log a security finding."""
        finding = {
            'category': category,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'remediation': remediation
        }
        self.findings.append(finding)
        severity_icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
        print(f"\n{severity_icon.get(severity, '⚪')} [{severity}] {category}")
        print(f"   {description}")
        if evidence:
            print(f"   Evidence: {evidence[:100]}...")
        if remediation:
            print(f"   Fix: {remediation}")
    
    def check_wordpress_version(self):
        """Detect WordPress version and check for known vulnerabilities."""
        print("\n" + "="*60)
        print("WORDPRESS VERSION DETECTION")
        print("="*60)
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text
            
            # Check meta generator tag
            generator_match = re.search(
                r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']WordPress\s+([\d.]+)',
                content, re.IGNORECASE
            )
            if generator_match:
                version = generator_match.group(1)
                print(f"✓ WordPress version detected: {version}")
                
                # Check for outdated versions (example)
                if version < '6.0':
                    self.log_finding(
                        'Outdated WordPress',
                        'High',
                        f'WordPress {version} is outdated',
                        f'Version: {version}',
                        'Update to the latest WordPress version'
                    )
                return version
            
            # Check readme.html
            readme_response = self.session.get(
                f'{self.target_url}/readme.html', timeout=10
            )
            if readme_response.status_code == 200:
                version_match = re.search(
                    r'Version\s+([\d.]+)', readme_response.text
                )
                if version_match:
                    version = version_match.group(1)
                    print(f"✓ WordPress version from readme.html: {version}")
                    self.log_finding(
                        'Information Disclosure',
                        'Medium',
                        'readme.html exposes WordPress version',
                        f'Version: {version}',
                        'Remove or restrict access to readme.html'
                    )
                    return version
            
            print("✗ Could not determine WordPress version")
            return None
            
        except Exception as e:
            print(f"✗ Error checking version: {e}")
            return None
    
    def check_login_security(self):
        """Test wp-login.php for security issues."""
        print("\n" + "="*60)
        print("LOGIN FORM SECURITY TEST")
        print("="*60)
        
        login_url = f'{self.target_url}/wp-login.php'
        
        try:
            response = self.session.get(login_url, timeout=10)
            
            if response.status_code == 200:
                print(f"✓ Login page accessible: {login_url}")
                
                # Check for default credentials (educational - don't actually try passwords)
                print("\n📋 Testing input validation...")
                
                # Test SQL injection in username field
                test_payloads = [
                    ("admin' OR '1'='1", "Basic OR injection"),
                    ("admin'--", "Comment injection"),
                    ("admin' AND SLEEP(1)--", "Time-based probe"),
                ]
                
                for payload, description in test_payloads:
                    print(f"\n   Testing: {description}")
                    print(f"   Payload: {payload[:30]}...")
                    
                    start_time = time.time()
                    response = self.session.post(
                        login_url,
                        data={'log': payload, 'pwd': 'test', 'wp-submit': 'Log In'},
                        timeout=15,
                        allow_redirects=False
                    )
                    elapsed = time.time() - start_time
                    
                    # Check for error messages
                    if 'error' in response.text.lower():
                        # Analyze error message for information disclosure
                        if 'sql' in response.text.lower() or 'mysql' in response.text.lower():
                            self.log_finding(
                                'SQL Injection',
                                'Critical',
                                'SQL error message disclosed in login form',
                                response.text[:200],
                                'Implement proper error handling and prepared statements'
                            )
                        elif 'invalid' in response.text.lower():
                            print(f"   ✓ Generic error message (good)")
                        else:
                            print(f"   ℹ Response received")
                    
                    # Check for time-based indication
                    if elapsed > 5:
                        self.log_finding(
                            'Time-Based SQLi',
                            'High',
                            'Login response delayed significantly',
                            f'Delay: {elapsed:.2f}s',
                            'Investigate potential time-based SQL injection'
                        )
                    else:
                        print(f"   Response time: {elapsed:.2f}s")
                
            else:
                print(f"✗ Login page returned status: {response.status_code}")
                
        except Exception as e:
            print(f"✗ Error testing login: {e}")
    
    def check_rest_api(self):
        """Test REST API endpoints for security issues."""
        print("\n" + "="*60)
        print("REST API SECURITY TEST")
        print("="*60)
        
        api_endpoints = [
            '/wp-json/wp/v2/posts',
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/comments',
            '/wp-json/wp/v2/categories',
            '/wp-json/wp/v2/pages',
            '/wp-json/wp/v2/media',
        ]
        
        for endpoint in api_endpoints:
            url = f'{self.target_url}{endpoint}'
            print(f"\n🔍 Testing: {endpoint}")
            
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    print(f"   ✓ Endpoint accessible")
                    
                    # Check for user enumeration
                    if '/users' in endpoint:
                        try:
                            users = response.json()
                            if users and isinstance(users, list):
                                print(f"   ⚠ User enumeration possible ({len(users)} users found)")
                                self.log_finding(
                                    'User Enumeration',
                                    'Medium',
                                    'REST API exposes user information',
                                    f'Found {len(users)} users',
                                    'Restrict REST API access for unauthenticated users'
                                )
                        except:
                            pass
                    
                    # Test pagination parameters
                    paginated_url = f'{url}?per_page=100&page=1'
                    paginated_response = self.session.get(paginated_url, timeout=10)
                    
                    if paginated_response.status_code == 200:
                        print(f"   ✓ Pagination parameters accepted")
                    
                    # Test search parameter
                    search_url = f'{url}?search=test'
                    search_response = self.session.get(search_url, timeout=10)
                    
                    if search_response.status_code == 200:
                        print(f"   ✓ Search parameter accepted")
                        
                elif response.status_code == 401 or response.status_code == 403:
                    print(f"   ✓ Endpoint requires authentication")
                else:
                    print(f"   ℹ Status: {response.status_code}")
                    
            except Exception as e:
                print(f"   ✗ Error: {e}")
    
    def check_plugins_themes(self):
        """Detect installed plugins and themes."""
        print("\n" + "="*60)
        print("PLUGIN & THEME DETECTION")
        print("="*60)
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text
            
            # Detect plugins
            plugin_pattern = r'wp-content/plugins/([^/"]+)'
            plugins = set(re.findall(plugin_pattern, content))
            
            if plugins:
                print(f"\n📦 Detected plugins ({len(plugins)}):")
                for plugin in sorted(plugins):
                    print(f"   • {plugin}")
            else:
                print("\n✗ No plugins detected in source")
            
            # Detect themes
            theme_pattern = r'wp-content/themes/([^/"]+)'
            themes = set(re.findall(theme_pattern, content))
            
            if themes:
                print(f"\n🎨 Detected themes ({len(themes)}):")
                for theme in sorted(themes):
                    print(f"   • {theme}")
            else:
                print("\n✗ No themes detected in source")
            
            # Check for common vulnerable paths
            sensitive_paths = [
                '/wp-config.php.bak',
                '/wp-config.php~',
                '/wp-config.php.old',
                '/.wp-config.php.swp',
                '/wp-config.php.save',
                '/wp-config.php.txt',
                '/phpinfo.php',
                '/info.php',
                '/test.php',
                '/.env',
                '/debug.log',
                '/wp-content/debug.log',
                '/wp-admin/install.php',
            ]
            
            print("\n🔍 Checking sensitive files...")
            for path in sensitive_paths:
                url = f'{self.target_url}{path}'
                try:
                    file_response = self.session.get(url, timeout=5, allow_redirects=False)
                    if file_response.status_code == 200:
                        # Check if it's actually a sensitive file (not just 404 page)
                        if len(file_response.text) > 100:
                            self.log_finding(
                                'Information Disclosure',
                                'High',
                                f'Sensitive file accessible: {path}',
                                f'Status: {file_response.status_code}',
                                f'Restrict access to {path}'
                            )
                except:
                    pass
                    
        except Exception as e:
            print(f"✗ Error checking plugins/themes: {e}")
    
    def check_security_headers(self):
        """Check for security headers."""
        print("\n" + "="*60)
        print("SECURITY HEADERS CHECK")
        print("="*60)
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['SAMEORIGIN', 'DENY'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=',
                'Content-Security-Policy': 'default-src',
                'Referrer-Policy': 'strict-origin',
            }
            
            print("\nHeader Status:")
            for header, expected in security_headers.items():
                value = headers.get(header)
                if value:
                    print(f"   ✓ {header}: {value[:50]}...")
                else:
                    print(f"   ✗ {header}: Missing")
                    self.log_finding(
                        'Missing Security Header',
                        'Low',
                        f'Missing security header: {header}',
                        '',
                        f'Add {header} header to HTTP responses'
                    )
            
            # Check for server information disclosure
            server = headers.get('Server', '')
            if server:
                print(f"\n⚠ Server header exposes information: {server}")
                self.log_finding(
                    'Information Disclosure',
                    'Low',
                    'Server header exposes software information',
                    f'Server: {server}',
                    'Remove or obfuscate Server header'
                )
            
            # Check X-Powered-By
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                print(f"⚠ X-Powered-By header exposes: {powered_by}")
                self.log_finding(
                    'Information Disclosure',
                    'Low',
                    'X-Powered-By header exposes technology',
                    f'X-Powered-By: {powered_by}',
                    'Remove X-Powered-By header'
                )
                
        except Exception as e:
            print(f"✗ Error checking headers: {e}")
    
    def check_ssl_tls(self):
        """Check SSL/TLS configuration."""
        print("\n" + "="*60)
        print("SSL/TLS CONFIGURATION CHECK")
        print("="*60)
        
        if not self.target_url.startswith('https'):
            print("⚠ Site does not use HTTPS")
            self.log_finding(
                'No HTTPS',
                'High',
                'Site does not use HTTPS',
                '',
                'Enable HTTPS with a valid SSL certificate'
            )
            return
        
        print("✓ Site uses HTTPS")
        
        # Additional SSL checks would require ssl module
        # This is a simplified version
        try:
            response = self.session.get(self.target_url, timeout=10)
            # Check if HTTP redirects to HTTPS
            http_url = self.target_url.replace('https://', 'http://')
            try:
                http_response = self.session.get(http_url, timeout=10, allow_redirects=False)
                if http_response.status_code in [301, 302]:
                    location = http_response.headers.get('Location', '')
                    if 'https' in location:
                        print("✓ HTTP properly redirects to HTTPS")
                    else:
                        print("⚠ HTTP does not redirect to HTTPS")
                else:
                    print("⚠ HTTP does not redirect to HTTPS")
            except:
                print("ℹ Could not verify HTTP to HTTPS redirect")
                
        except Exception as e:
            print(f"✗ Error checking SSL: {e}")
    
    def generate_report(self):
        """Generate a summary report."""
        print("\n" + "="*60)
        print("SCAN REPORT SUMMARY")
        print("="*60)
        
        if not self.findings:
            print("\n✓ No security issues found!")
            return
        
        # Count by severity
        severity_counts = {}
        for finding in self.findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"\nTotal findings: {len(self.findings)}")
        print("\nBy severity:")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
                print(f"   {icon.get(severity, '⚪')} {severity}: {count}")
        
        print("\nDetailed findings:")
        for i, finding in enumerate(self.findings, 1):
            print(f"\n{i}. [{finding['severity']}] {finding['category']}")
            print(f"   {finding['description']}")
            if finding['remediation']:
                print(f"   Fix: {finding['remediation']}")
        
        print("\n" + "="*60)
        print("END OF REPORT")
        print("="*60)
    
    def run_scan(self):
        """Run all security checks."""
        print("\n" + "="*60)
        print("WORDPRESS SECURITY SCAN")
        print(f"Target: {self.target_url}")
        print("="*60)
        
        self.check_wordpress_version()
        self.check_login_security()
        self.check_rest_api()
        self.check_plugins_themes()
        self.check_security_headers()
        self.check_ssl_tls()
        self.generate_report()


def main():
    parser = argparse.ArgumentParser(
        description='WordPress Security Scanner - Educational Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --cookie "wordpress_logged_in=..."
  
DISCLAIMER: Only use this tool on systems you own or have explicit permission to test.
        """
    )
    
    parser.add_argument('url', help='Target WordPress URL')
    parser.add_argument('--cookie', help='Authentication cookie', default=None)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)
    
    # Run scanner
    scanner = WordPressSecurityScanner(args.url, args.cookie)
    scanner.run_scan()


if __name__ == '__main__':
    main()
