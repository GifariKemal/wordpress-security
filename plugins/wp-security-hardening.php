<?php
/**
 * WordPress Security Hardening Plugin
 * 
 * This plugin implements security best practices to protect WordPress
 * from SQL injection and other common attacks.
 * 
 * DISCLAIMER: This is for educational purposes. Always test thoroughly
 * before implementing in production.
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class WP_Security_Hardening {
    
    private static $instance = null;
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->init_hooks();
    }
    
    private function init_hooks() {
        // Add security headers
        add_action('send_headers', array($this, 'add_security_headers'));
        
        // Sanitize login errors to prevent user enumeration
        add_filter('login_errors', array($this, 'sanitize_login_errors'));
        
        // Remove WordPress version from head
        remove_action('wp_head', 'wp_generator');
        
        // Remove WordPress version from RSS
        add_filter('the_generator', '__return_empty_string');
        
        // Remove WordPress version from scripts and styles
        add_filter('style_loader_src', array($this, 'remove_version_strings'), 9999);
        add_filter('script_loader_src', array($this, 'remove_version_strings'), 9999);
        
        // Disable XML-RPC
        add_filter('xmlrpc_enabled', '__return_false');
        
        // Restrict REST API for unauthenticated users
        add_filter('rest_authentication_errors', array($this, 'restrict_rest_api'));
        
        // Disable file editing from admin
        if (!defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }
        
        // Add SQL injection protection
        add_filter('query', array($this, 'detect_sql_injection'));
        
        // Log security events
        add_action('wp_login_failed', array($this, 'log_failed_login'));
        add_action('wp_login', array($this, 'log_successful_login'));
        
        // Disable author archives for user enumeration prevention
        add_action('template_redirect', array($this, 'disable_author_archives'));
        
        // Add nonces to forms
        add_action('wp_enqueue_scripts', array($this, 'enqueue_security_scripts'));
        
        // Rate limit login attempts
        add_filter('authenticate', array($this, 'rate_limit_login'), 30, 3);
    }
    
    /**
     * Add security headers to HTTP responses
     */
    public function add_security_headers() {
        // Prevent MIME type sniffing
        header('X-Content-Type-Options: nosniff');
        
        // Prevent clickjacking
        header('X-Frame-Options: SAMEORIGIN');
        
        // Enable XSS protection
        header('X-XSS-Protection: 1; mode=block');
        
        // Referrer policy
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Content Security Policy (customize as needed)
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;");
        
        // Strict Transport Security (if using HTTPS)
        if (is_ssl()) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
        
        // Permissions Policy
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    }
    
    /**
     * Sanitize login error messages to prevent user enumeration
     */
    public function sanitize_login_errors($error) {
        // Generic error message that doesn't reveal if username exists
        return '<strong>ERROR</strong>: Invalid username or password.';
    }
    
     * Remove version strings from enqueued scripts and styles
     */
    public function remove_version_strings($src) {
        if (strpos($src, 'ver=')) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }
    
    /**
     * Restrict REST API access for unauthenticated users
     */
    public function restrict_rest_api($result) {
        // Allow authenticated requests
        if (!empty($result) || is_user_logged_in()) {
            return $result;
        }
        
        // Allow specific endpoints that need public access
        $public_endpoints = array(
            '/wp-json/wp/v2/posts',
            '/wp-json/wp/v2/pages',
            '/wp-json/wp/v2/categories',
            '/wp-json/wp/v2/tags',
        );
        
        $current_endpoint = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        
        if (in_array($current_endpoint, $public_endpoints)) {
            return $result;
        }
        
        // Block other endpoints for unauthenticated users
        return new WP_Error(
            'rest_forbidden',
            __('REST API access restricted.'),
            array('status' => 403)
        );
    }
    
    /**
     * Detect potential SQL injection attempts
     */
    public function detect_sql_injection($query) {
        // Common SQL injection patterns
        $patterns = array(
            '/UNION\s+SELECT/i',
            '/SELECT\s+.*FROM/i',
            '/INSERT\s+INTO/i',
            '/DELETE\s+FROM/i',
            '/DROP\s+TABLE/i',
            '/UPDATE\s+.*SET/i',
            '/OR\s+1\s*=\s*1/i',
            '/AND\s+1\s*=\s*1/i',
            '/\'\s*OR\s*\'/i',
            '/--\s*$/',
            '/;\s*DROP/i',
            '/SLEEP\s*\(/i',
            '/BENCHMARK\s*\(/i',
            '/WAITFOR\s+DELAY/i',
        );
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $query)) {
                // Log the attempt
                $this->log_security_event('sql_injection_attempt', array(
                    'query' => substr($query, 0, 200),
                    'ip' => $this->get_client_ip(),
                    'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
                ));
                
                // Optionally block the request
                // wp_die('Security violation detected.', 'Security Error', array('response' => 403));
            }
        }
        
        return $query;
    }
    
    /**
     * Rate limit login attempts
     */
    public function rate_limit_login($user, $username, $password) {
        if (empty($username)) {
            return $user;
        }
        
        $ip = $this->get_client_ip();
        $transient_key = 'login_attempts_' . md5($ip);
        $attempts = get_transient($transient_key);
        
        if ($attempts === false) {
            $attempts = 0;
        }
        
        // Max 5 attempts per 15 minutes
        if ($attempts >= 5) {
            return new WP_Error(
                'too_many_attempts',
                '<strong>ERROR</strong>: Too many login attempts. Please try again later.'
            );
        }
        
        // Increment attempts
        set_transient($transient_key, $attempts + 1, 15 * MINUTE_IN_SECONDS);
        
        return $user;
    }
    
    /**
     * Log failed login attempts
     */
    public function log_failed_login($username) {
        $this->log_security_event('failed_login', array(
            'username' => $username,
            'ip' => $this->get_client_ip(),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
        ));
    }
    
    /**
     * Log successful logins
     */
    public function log_successful_login($user_login) {
        $this->log_security_event('successful_login', array(
            'username' => $user_login,
            'ip' => $this->get_client_ip(),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
        ));
    }
    
    /**
     * Disable author archives to prevent user enumeration
     */
    public function disable_author_archives() {
        if (is_author()) {
            wp_redirect(home_url(), 301);
            exit;
        }
    }
    
    /**
     * Enqueue security-related scripts
     */
    public function enqueue_security_scripts() {
        // Add nonce to AJAX requests
        wp_localize_script('jquery', 'wpSecurity', array(
            'ajax_nonce' => wp_create_nonce('wp_security_nonce'),
        ));
    }
    
    /**
     * Log security events
     */
    private function log_security_event($event_type, $data) {
        $log_entry = array(
            'timestamp' => current_time('mysql'),
            'event_type' => $event_type,
            'data' => $data,
        );
        
        // Store in options (in production, use a proper logging system)
        $logs = get_option('wp_security_logs', array());
        $logs[] = $log_entry;
        
        // Keep only last 1000 entries
        if (count($logs) > 1000) {
            $logs = array_slice($logs, -1000);
        }
        
        update_option('wp_security_logs', $logs);
        
        // Also log to file if writable
        $log_file = WP_CONTENT_DIR . '/security.log';
        if (is_writable(WP_CONTENT_DIR)) {
            $log_line = sprintf(
                "[%s] %s: %s\n",
                $log_entry['timestamp'],
                $event_type,
                json_encode($data)
            );
            file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);
        }
    }
    
    /**
     * Get client IP address
     */
    private function get_client_ip() {
        $ip_keys = array(
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );
        
        foreach ($ip_keys as $key) {
            if (isset($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                // Handle comma-separated IPs
                if (strpos($ip, ',') !== false) {
                    $ip = explode(',', $ip)[0];
                }
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return '0.0.0.0';
    }
    
    /**
     * Get security logs
     */
    public function get_logs($limit = 100) {
        $logs = get_option('wp_security_logs', array());
        return array_slice($logs, -$limit);
    }
    
    /**
     * Clear security logs
     */
    public function clear_logs() {
        delete_option('wp_security_logs');
    }
}

// Initialize the plugin
WP_Security_Hardening::get_instance();

/**
 * Admin page for viewing security logs
 */
class WP_Security_Admin_Page {
    
    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
    }
    
    public function add_admin_menu() {
        add_options_page(
            'Security Logs',
            'Security Logs',
            'manage_options',
            'wp-security-logs',
            array($this, 'render_admin_page')
        );
    }
    
    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Handle clear logs action
        if (isset($_POST['clear_logs']) && wp_verify_nonce($_POST['_wpnonce'], 'clear_logs')) {
            WP_Security_Hardening::get_instance()->clear_logs();
            echo '<div class="notice notice-success"><p>Logs cleared.</p></div>';
        }
        
        $logs = WP_Security_Hardening::get_instance()->get_logs(100);
        
        ?>
        <div class="wrap">
            <h1>Security Logs</h1>
            
            <form method="post">
                <?php wp_nonce_field('clear_logs'); ?>
                <input type="submit" name="clear_logs" class="button" value="Clear Logs">
            </form>
            
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach (array_reverse($logs) as $log): ?>
                    <tr>
                        <td><?php echo esc_html($log['timestamp']); ?></td>
                        <td>
                            <?php 
                            $type_labels = array(
                                'failed_login' => '🔴 Failed Login',
                                'successful_login' => '🟢 Successful Login',
                                'sql_injection_attempt' => '🔴 SQL Injection Attempt',
                            );
                            echo isset($type_labels[$log['event_type']]) ? $type_labels[$log['event_type']] : esc_html($log['event_type']);
                            ?>
                        </td>
                        <td><?php echo esc_html(json_encode($log['data'])); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php
    }
}

new WP_Security_Admin_Page();
