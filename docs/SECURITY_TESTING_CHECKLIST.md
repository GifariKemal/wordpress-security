# WordPress SQL Injection Security Testing Checklist

> **IMPORTANT**: Only use this checklist on systems you own or have explicit written permission to test.

## Pre-Testing Setup

### Authorization
- [ ] Written permission obtained from system owner
- [ ] Scope of testing defined
- [ ] Testing environment identified (production/staging/development)
- [ ] Emergency contacts established
- [ ] Legal review completed (if required)

### Tools Preparation
- [ ] SQLMap installed and configured
- [ ] Burp Suite/OWASP ZAP configured
- [ ] Browser developer tools ready
- [ ] Custom scripts prepared
- [ ] Logging/monitoring tools set up

### Documentation
- [ ] Testing methodology documented
- [ ] Reporting template prepared
- [ ] Evidence collection process defined

---

## Phase 1: Information Gathering

### WordPress Version Detection
- [ ] Check meta generator tag
- [ ] Check readme.html
- [ ] Check feed/rdf for version
- [ ] Check wp-includes/version.php (if accessible)
- [ ] Document version number

### Plugin & Theme Detection
- [ ] Scan for wp-content/plugins/ references
- [ ] Scan for wp-content/themes/ references
- [ ] Check for common plugin paths
- [ ] Document all detected plugins/themes
- [ ] Check for outdated versions

### User Enumeration
- [ ] Test /wp-json/wp/v2/users endpoint
- [ ] Test ?author=1 parameter
- [ ] Test login error messages
- [ ] Check /feed/ for author information
- [ ] Document discovered usernames

### REST API Endpoints
- [ ] Test /wp-json/wp/v2/posts
- [ ] Test /wp-json/wp/v2/pages
- [ ] Test /wp-json/wp/v2/comments
- [ ] Test /wp-json/wp/v2/users
- [ ] Test /wp-json/wp/v2/categories
- [ ] Test /wp-json/wp/v2/tags
- [ ] Document accessible endpoints

---

## Phase 2: SQL Injection Testing

### Input Validation Testing

#### Login Form (wp-login.php)
- [ ] Test username field with single quote (')
- [ ] Test username field with double quote (")
- [ ] Test username field with semicolon (;)
- [ ] Test username field with comment sequences (--, #, /*)
- [ ] Test password field with special characters
- [ ] Test redirect_to parameter
- [ ] Check for error message disclosure
- [ ] Check for time-based indicators

#### Search Functionality
- [ ] Test search parameter with single quote
- [ ] Test search parameter with UNION SELECT
- [ ] Test search parameter with OR/AND conditions
- [ ] Test search parameter with time-based payloads
- [ ] Check response differences

#### REST API Parameters
- [ ] Test per_page parameter
- [ ] Test page parameter
- [ ] Test search parameter
- [ ] Test filter parameters
- [ ] Test orderby parameter
- [ ] Test order parameter

#### URL Parameters
- [ ] Test permalink parameters
- [ ] Test category/tag parameters
- [ ] Test pagination parameters
- [ ] Test custom query parameters

### Error-Based Detection
- [ ] Submit single quote and check for SQL errors
- [ ] Submit double quote and check for SQL errors
- [ ] Submit malformed SQL and check for errors
- [ ] Check for MySQL error messages
- [ ] Check for database information disclosure
- [ ] Document any error messages

### Boolean-Based Detection
- [ ] Test with true condition (AND 1=1)
- [ ] Test with false condition (AND 1=2)
- [ ] Compare response sizes
- [ ] Compare response content
- [ ] Compare response times
- [ ] Document differences

### Time-Based Detection
- [ ] Test with SLEEP() function
- [ ] Test with BENCHMARK() function
- [ ] Test with WAITFOR DELAY
- [ ] Measure response times
- [ ] Document time differences

### Union-Based Detection
- [ ] Determine number of columns
- [ ] Test UNION SELECT with different column counts
- [ ] Test UNION SELECT with NULL values
- [ ] Check for data extraction possibilities
- [ ] Document findings

---

## Phase 3: WordPress-Specific Vectors

### Authentication Bypass Testing
- [ ] Test for authentication bypass via SQLi
- [ ] Test cookie manipulation
- [ ] Test session fixation
- [ ] Test nonce bypass attempts

### Plugin-Specific Testing
- [ ] Identify high-risk plugins (forms, e-commerce, etc.)
- [ ] Test plugin AJAX handlers
- [ ] Test plugin admin pages
- [ ] Test plugin shortcodes
- [ ] Check for known vulnerabilities (CVE databases)

### Theme-Specific Testing
- [ ] Test theme AJAX handlers
- [ ] Test theme template queries
- [ ] Test theme options pages
- [ ] Check for known vulnerabilities

### Database Enumeration
- [ ] Extract current database name
- [ ] List all databases
- [ ] List tables in WordPress database
- [ ] List columns in wp_users table
- [ ] Extract user credentials (if authorized)
- [ ] Extract sensitive data (if authorized)

---

## Phase 4: Automated Testing

### SQLMap Configuration
- [ ] Configure authentication (cookies)
- [ ] Set appropriate level (1-5)
- [ ] Set appropriate risk (1-3)
- [ ] Configure tamper scripts (if WAF present)
- [ ] Set request delay (if needed)
- [ ] Configure output directory

### SQLMap Execution
- [ ] Test GET parameters
- [ ] Test POST parameters
- [ ] Test cookie values
- [ ] Test HTTP headers
- [ ] Run with --forms flag
- [ ] Run with --crawl flag
- [ ] Document all findings

### Burp Suite/OWASP ZAP
- [ ] Configure proxy
- [ ] Spider the application
- [ ] Run active scan
- [ ] Review findings
- [ ] Verify findings manually

---

## Phase 5: WAF/IPS Evasion (if applicable)

### Detection
- [ ] Identify if WAF/IPS is present
- [ ] Identify WAF type (if possible)
- [ ] Document blocking behavior

### Evasion Techniques
- [ ] Try case variation (SeLeCt)
- [ ] Try comment insertion (SEL/**/ECT)
- [ ] Try encoding (URL, Unicode, Base64)
- [ ] Try HTTP parameter pollution
- [ ] Try chunked transfer encoding
- [ ] Try different HTTP methods
- [ ] Document successful techniques

---

## Phase 6: Evidence Collection

### Screenshots
- [ ] Screenshot of vulnerable parameter
- [ ] Screenshot of SQLi payload
- [ ] Screenshot of successful injection
- [ ] Screenshot of extracted data
- [ ] Screenshot of error messages

### Request/Response Logs
- [ ] Save vulnerable requests
- [ ] Save responses showing injection
- [ ] Save error messages
- [ ] Save extracted data

### Tool Output
- [ ] Save SQLMap output
- [ ] Save Burp Suite/ZAP reports
- [ ] Save custom script output

---

## Phase 7: Reporting

### Vulnerability Report Contents
- [ ] Title and description
- [ ] Severity rating (Critical/High/Medium/Low)
- [ ] Affected component
- [ ] Steps to reproduce
- [ ] Proof of concept
- [ ] Impact assessment
- [ ] Remediation recommendations
- [ ] References (CVE, advisories)

### Documentation
- [ ] Executive summary
- [ ] Technical details
- [ ] Risk assessment
- [ ] Remediation priorities
- [ ] Follow-up recommendations

---

## Phase 8: Remediation Verification

### After Fixes Applied
- [ ] Re-test vulnerable endpoints
- [ ] Verify SQL injection is prevented
- [ ] Verify error messages are generic
- [ ] Verify input validation works
- [ ] Verify prepared statements are used
- [ ] Document verification results

---

## Quick Reference: SQL Injection Test Payloads

### Basic Tests
```
'
"
'
"
--
#
/*
```

### Boolean Tests
```
AND 1=1
AND 1=2
OR 1=1
OR 1=2
```

### Time-Based Tests
```
AND SLEEP(5)
AND BENCHMARK(10000000,SHA1('test'))
WAITFOR DELAY '0:0:5'
```

### Union Tests
```
UNION SELECT NULL
UNION SELECT NULL,NULL
UNION SELECT NULL,NULL,NULL
UNION SELECT 1,2,3
```

### Comment Tests
```
'/*
'#
'--
```

---

## Common WordPress SQL Injection Locations

1. **wp-login.php** - Username/password fields
2. **wp-admin/admin-ajax.php** - Action parameters
3. **wp-admin/admin.php** - Page parameters
4. **/wp-json/wp/v2/** - REST API endpoints
5. **/?s=** - Search parameter
6. **/?cat=** - Category parameter
7. **/?tag=** - Tag parameter
8. **/?p=** - Post parameter
9. **/?page_id=** - Page parameter
10. **/?author=** - Author parameter

---

## Tools Reference

### SQLMap
```bash
# Basic scan
sqlmap -u "URL" --batch

# With authentication
sqlmap -u "URL" --cookie="COOKIE" --batch

# With tamper scripts
sqlmap -u "URL" --tamper=space2comment,randomcase --batch

# Full scan
sqlmap -u "URL" --level=5 --risk=3 --batch
```

### WPScan
```bash
# Basic scan
wpscan --url https://example.com

# Enumerate plugins
wpscan --url https://example.com --enumerate p

# Enumerate themes
wpscan --url https://example.com --enumerate t

# Enumerate users
wpscan --url https://example.com --enumerate u
```

### curl
```bash
# Test GET parameter
curl "https://example.com/?id=1'"

# Test POST parameter
curl -X POST "https://example.com/wp-login.php" \
  -d "log=admin'&pwd=test"

# Test with headers
curl -H "X-Forwarded-For: 127.0.0.1'" "https://example.com/"
```

---

## Notes

- Always test in a controlled environment first
- Document everything for your report
- Don't modify production data
- Report findings responsibly
- Follow up on remediation

---

**Last Updated**: 2026-06-15

**Remember**: This checklist is for authorized security testing only. Unauthorized access to computer systems is illegal.
