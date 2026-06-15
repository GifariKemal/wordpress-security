# WordPress Security Testing Resources

> **DISCLAIMER**: All tools and documentation in this repository are for **authorized security testing only**. Always obtain written permission before testing any system you don't own. Unauthorized access to computer systems is illegal.

## 📚 Documentation

- [Security Testing Guide](SECURITY_TESTING_GUIDE.md) - Comprehensive guide to WordPress security testing
- [SQLMap Advanced Guide](docs/sqlmap_advanced_guide.md) - Advanced SQLMap configuration for WordPress

## 🛠️ Tools

### Security Scanner

A Python-based WordPress security scanner for educational purposes.

**Installation:**
```bash
pip install requests
```

**Usage:**
```bash
# Basic scan
python scripts/wp_security_scanner.py https://example.com

# With authentication cookie
python scripts/wp_security_scanner.py https://example.com --cookie "wordpress_logged_in=..."
```

**Features:**
- WordPress version detection
- Login form security testing
- REST API endpoint testing
- Plugin/theme detection
- Security header checks
- SSL/TLS configuration verification
- Vulnerability reporting

### Security Hardening Plugin

A WordPress plugin that implements security best practices.

**Installation:**
1. Copy `plugins/wp-security-hardening.php` to your WordPress plugins directory
2. Activate the plugin in WordPress admin

**Features:**
- Security headers (X-Content-Type-Options, X-Frame-Options, etc.)
- Login error sanitization (prevents user enumeration)
- REST API access restriction
- SQL injection attempt detection
- Login rate limiting
- Security event logging
- Admin page for viewing logs

## 📖 Resources

### Official Documentation
- [WordPress Security Codex](https://developer.wordpress.org/apis/security/)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Security Tools
- [SQLMap](https://sqlmap.org/) - Automatic SQL injection tool
- [OWASP ZAP](https://www.zaproxy.org/) - Web application security scanner
- [Burp Suite](https://portswigger.net/burp) - Web vulnerability scanner
- [WPScan](https://wpscan.org/) - WordPress security scanner

### Training Platforms
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)

## 🔒 Security Best Practices

### For WordPress Developers

1. **Use Prepared Statements**
   ```php
   // Always use $wpdb->prepare()
   $wpdb->query($wpdb->prepare(
       "SELECT * FROM {$wpdb->posts} WHERE ID = %d",
       $post_id
   ));
   ```

2. **Validate and Sanitize Input**
   ```php
   $sanitized = sanitize_text_field($_GET['param']);
   $email = sanitize_email($_POST['email']);
   $url = esc_url($_POST['website']);
   ```

3. **Use Nonces for Forms**
   ```php
   wp_nonce_field('my_action', 'my_nonce');
   if (!wp_verify_nonce($_POST['my_nonce'], 'my_action')) {
       die('Security check failed');
   }
   ```

4. **Check User Capabilities**
   ```php
   if (!current_user_can('manage_options')) {
       wp_die('Unauthorized');
   }
   ```

5. **Keep Everything Updated**
   - WordPress core
   - Plugins
   - Themes
   - PHP version

### For Security Testers

1. **Always Get Authorization**
   - Written permission before testing
   - Define scope and boundaries
   - Document everything

2. **Use Safe Testing Methods**
   - Don't modify production data
   - Use test environments when possible
   - Report findings responsibly

3. **Follow Responsible Disclosure**
   - Report to vendor/owner first
   - Allow time for fixes
   - Don't publish vulnerabilities prematurely

## 📊 Common Vulnerabilities

### SQL Injection in WordPress

**Vulnerable Code:**
```php
// BAD: Direct query without preparation
$results = $wpdb->get_results(
    "SELECT * FROM {$wpdb->posts} WHERE post_title = '" . $_GET['title'] . "'"
);
```

**Secure Code:**
```php
// GOOD: Using prepared statements
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->posts} WHERE post_title = %s",
        sanitize_text_field($_GET['title'])
    )
);
```

### User Enumeration

**Vulnerable:**
- `/wp-json/wp/v2/users` exposes user list
- `?author=1` reveals username
- Login error messages reveal if username exists

**Mitigation:**
- Restrict REST API access
- Disable author archives
- Use generic error messages

## 🚨 Reporting Vulnerabilities

If you discover a security vulnerability in WordPress or a plugin/theme:

1. **WordPress Core**: [HackerOne Program](https://hackerone.com/wordpress)
2. **Plugins**: Contact the plugin author directly
3. **Themes**: Contact the theme author directly

## 📝 License

This repository is for educational purposes only. Use responsibly and ethically.

---

**Remember:** Security testing is about making systems safer, not exploiting them. Always act ethically and within legal boundaries.
