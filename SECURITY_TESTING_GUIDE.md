# WordPress SQL Injection Security Testing Guide

> **DISCLAIMER**: This document is for **authorized security testing only**. Always obtain written permission before testing any system you don't own. Unauthorized access to computer systems is illegal.

## Table of Contents
1. [SQL Injection Fundamentals](#1-sql-injection-fundamentals)
2. [Detection Methods](#2-detection-methods)
3. [WordPress-Specific Vectors](#3-wordpress-specific-vectors)
4. [Security Tools & Configuration](#4-security-tools--configuration)
5. [Defensive Measures](#5-defensive-measures)
6. [Reporting & Remediation](#6-reporting--remediation)

---

## 1. SQL Injection Fundamentals

### What is SQL Injection?
SQL injection occurs when user input is improperly incorporated into SQL queries, allowing attackers to manipulate database operations.

### Common Vulnerability Points in WordPress
- Login forms (wp-login.php)
- Search functionality
- URL parameters (permalinks)
- REST API endpoints (/wp-json/wp/v2/)
- Plugin/theme AJAX handlers
- Admin panel forms
- Cookie values

### Input Validation Testing
Test if application properly sanitizes:
- Special characters: `'`, `"`, `;`, `--`, `/*`
- SQL keywords: `SELECT`, `UNION`, `OR`, `AND`
- Comment sequences: `#`, `-- `, `/* */`

---

## 2. Detection Methods

### Basic Detection Techniques

**Error-Based Detection:**
Look for database error messages in responses that indicate SQL processing issues.

```
Test: Add single quote to parameters
Expected behavior: Application should reject or sanitize input
Red flag: Database error messages exposed to users
```

**Boolean-Based Detection:**
```
Test: Submit true/false conditions in input
Example: Input that should return results vs. input that shouldn't
Red flag: Different responses based on injected conditions
```

**Time-Based Detection:**
```
Test: Submit input that would cause delays if processed
Example: Commands that force database to wait
Red flag: Response time varies based on injected delays
```

### What to Look For
- HTTP 500 errors with database details
- Different response sizes/content for similar inputs
- Unexpected delays in response times
- Information leakage in error messages

---

## 3. WordPress-Specific Vectors

### 3.1 Authentication Endpoints

**wp-login.php Testing:**
- Username field input validation
- Password field input validation
- `redirect_to` parameter validation
- Cookie-based authentication tokens

**wp-admin AJAX Handlers:**
- admin-ajax.php action parameters
- Nonce validation bypass attempts
- Capability check verification

### 3.2 REST API Endpoints

**Common Endpoints to Test:**
```
/wp-json/wp/v2/posts
/wp-json/wp/v2/users
/wp-json/wp/v2/comments
/wp-json/wp/v2/categories
```

**Testing Focus:**
- Query parameter validation
- Pagination parameters (per_page, page)
- Search parameters
- Filter parameters

### 3.3 Plugin Vulnerabilities

**Common Plugin Issues:**
- Direct database queries without prepared statements
- Missing nonce verification
- Insufficient capability checks
- Unsanitized user input in SQL queries

**High-Risk Plugins:**
- Form builders (contact forms, etc.)
- E-commerce plugins (WooCommerce, etc.)
- Page builders
- SEO plugins
- Backup plugins

### 3.4 Theme Vulnerabilities

**Common Theme Issues:**
- Custom template queries
- AJAX handlers
- Search functionality
- Custom post type queries

---

## 4. Security Tools & Configuration

### 4.1 SQLMap (Open Source)

**Basic Usage for Authorized Testing:**
```bash
# Basic scan (test mode only)
sqlmap -u "https://example.com/page?id=1" --batch --test-skip=basic

# With authentication
sqlmap -u "https://example.com/wp-admin/admin-ajax.php" \
  --cookie="wordpress_logged_in=..." \
  --data="action=test&param=value" \
  --batch

# REST API testing
sqlmap -u "https://example.com/wp-json/wp/v2/posts?per_page=10" \
  --batch \
  --level=3 \
  --risk=2
```

**SQLMap Configuration Options:**
```bash
# Limit to specific techniques
--technique=BEUSTQ  # Boolean, Error, Union, Stacked, Time, Query

# Control testing depth
--level=1-5    # Level of tests to perform
--risk=1-3     # Risk of tests (1=safe, 2=medium, 3=high)

# Custom headers
--headers="X-Forwarded-For: 127.0.0.1"

# Output control
--output-dir=/path/to/results
--forms         # Auto-test forms
--crawl=3       # Crawl depth
```

### 4.2 Burp Suite Configuration

**Setup for WordPress Testing:**
1. Configure proxy to intercept traffic
2. Add target to scope
3. Configure authentication handling
4. Set up session handling rules for nonces

**Intruder Positions:**
- Mark injection points in requests
- Use appropriate attack types (Sniper, Battering Ram, etc.)
- Configure payload processing rules

**Scanner Configuration:**
- Enable SQL injection checks
- Configure scan speed vs. accuracy
- Set up issue definitions for custom checks

### 4.3 OWASP ZAP

**Automated Scanning:**
1. Spider the WordPress site
2. Configure authentication (form-based, cookie-based)
3. Run active scan with SQL injection rules
4. Review findings

### 4.4 Manual Testing Tools

**Browser Developer Tools:**
- Network tab: Monitor requests/responses
- Console: JavaScript-based testing
- Application tab: Cookie manipulation

**Command Line Tools:**
```bash
# curl for basic testing
curl -X POST "https://example.com/wp-login.php" \
  -d "log=test&pwd=test&wp-submit=Log+In"

# httpie for REST API testing
http GET "https://example.com/wp-json/wp/v2/posts" \
  per_page==10 search=="test"
```

---

## 5. Defensive Measures

### 5.1 Input Validation & Sanitization

**WordPress Best Practices:**
```php
// Always use prepared statements
global $wpdb;
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->posts} WHERE post_title = %s",
        $user_input
    )
);

// Sanitize input
$sanitized = sanitize_text_field($_GET['param']);
$sanitized = esc_sql($_GET['param']);  // Escape for SQL

// Validate input type
if (!is_numeric($_GET['id'])) {
    wp_die('Invalid ID');
}
```

### 5.2 WordPress Security Hardening

**wp-config.php Security:**
```php
// Disable file editing
define('DISALLOW_FILE_EDIT', true);

// Force SSL for admin
define('FORCE_SSL_ADMIN', true);

// Limit post revisions
define('WP_POST_REVISIONS', 3);

// Automatic updates
define('WP_AUTO_UPDATE_CORE', true);
```

**Security Headers (in .htaccess or server config):**
```apache
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "SAMEORIGIN"
Header set X-XSS-Protection "1; mode=block"
Header set Referrer-Policy "strict-origin-when-cross-origin"
```

### 5.3 Plugin Security

**Recommended Security Plugins:**
- Wordfence Security
- Sucuri Security
- iThemes Security
- All In One WP Security

**Configuration:**
- Enable firewall rules
- Enable malware scanning
- Configure login security (rate limiting, 2FA)
- Enable audit logging
- Block malicious IPs

### 5.4 Database Security

**Principle of Least Privilege:**
```sql
-- Create limited database user
CREATE USER 'wp_user'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON wordpress_db.* TO 'wp_user'@'localhost';
FLUSH PRIVILEGES;
```

**Regular Maintenance:**
- Keep WordPress core updated
- Update plugins/themes regularly
- Remove unused plugins/themes
- Regular database backups
- Monitor database logs

---

## 6. Reporting & Remediation

### 6.1 Vulnerability Reporting Template

```markdown
## Vulnerability Report

**Title:** [Brief description]

**Severity:** Critical/High/Medium/Low

**Affected Component:** [Plugin/Theme/Core]

**Version:** [Version number]

**Description:**
[Detailed description of vulnerability]

**Steps to Reproduce:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Impact:**
[What an attacker could achieve]

**Proof of Concept:**
[Safe demonstration]

**Remediation:**
[Specific fix recommendations]

**References:**
- CVE-XXXX-XXXXX (if applicable)
- [Related advisories]
```

### 6.2 Remediation Checklist

- [ ] Implement parameterized queries/prepared statements
- [ ] Add input validation and sanitization
- [ ] Implement proper error handling (don't expose database errors)
- [ ] Add nonce verification to all forms/AJAX handlers
- [ ] Implement capability checks for admin functions
- [ ] Enable security headers
- [ ] Configure WAF rules
- [ ] Update all software components
- [ ] Implement logging and monitoring
- [ ] Conduct follow-up testing

---

## Additional Resources

### Documentation
- [WordPress Security Codex](https://developer.wordpress.org/apis/security/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Tools
- [SQLMap](https://sqlmap.org/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Burp Suite](https://portswigger.net/burp)
- [WPScan](https://wpscan.org/)

### Training
- OWASP WebGoat
- PortSwigger Web Security Academy
- HackTheBox
- TryHackMe

---

**Remember:** Always conduct security testing ethically and with proper authorization. Report vulnerabilities responsibly and help improve security for everyone.
