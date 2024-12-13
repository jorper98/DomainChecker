<?php
/**
 * Sample configuration file for Domain Checker
 * Copy this file to config.php and update the values with your actual settings
 */
return [
    'whois_api' => [
        // Your WhoisXML API key
        // Get one at: https://whois.whoisxmlapi.com
        'key' => 'your_whois_api_key_here',
        
        // Set to false to use native WHOIS lookup instead of API
        'enabled' => true
    ],
    
    'registration' => [
        // URL where users will be directed to register available domains
        'url' => 'https://your-registration-url.com/register'
    ],
    
    // Timeout in seconds for API and WHOIS requests
    'timeout' => 5
];