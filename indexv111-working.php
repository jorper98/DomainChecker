<?php
/**
 * AppName: Domain Checker
 * Description: PHP Script to check a domain name and if exists, then show the registration record and then show DNS records .  If it does not exist, then say so and if the variable is set, ovver to register it.
 * Version: 1.1.1
 * Author: Jorge Pereira
 */
 
 
// Enable error reporting for debugging (remove in production)
ini_set('display_errors', 0);
error_reporting(0);

class DomainChecker {
   private $timeout = 5;    
    private $whoisApiKey = 'at_W6dvX7qmvjmbBU4y8Xz2isiSavqyr'; // Replace with your WHOIS API key

    //  private $whoisApiKey = ''; // WhoisXMLAPI key (optional)
    private $useApi = true;    // Set to false to force native WHOIS
	private $txtRegistrationURL = "https://35sites.com/Register";

    private function logEvent(string $domain, bool $available) {
    $logFilePath = 'domain_checker.log'; // Adjust the path as needed
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "$timestamp - Domain: $domain - Availability: " . ($available ? 'Available' : 'Not Available') . "\n";

    file_put_contents($logFilePath, $logMessage, FILE_APPEND);
}

	
    public function checkAvailability(string $domain): array {
        try {
            // Clean up the domain input
            $domain = $this->cleanDomain($domain);
            
            // Validate the cleaned domain
            if (!$this->isValidDomain($domain)) {
                throw new Exception('Invalid domain format');
            }
            
            // Query DNS records using Google DNS-over-HTTPS
            $records = $this->getDnsRecordsSecure($domain);
            
            $result = [
                'domain' => $domain,
                'available' => empty($records),
                'records' => $records,
                'timestamp' => time()
            ];

            // If domain is registered, get WHOIS info
            if (!empty($records)) {
                $result['whois'] = $this->getWhoisInfo($domain);
            }
          
		  $this->logEvent($domain, $result['available']);

			if ($result['available']) {
				$result['message'] = "Secure this domain today! <a href='{$this->txtRegistrationURL}'>Register now</a>";
			}		  
			  
            return $result;
            
        } catch (Exception $e) {
            return [
                'error' => $e->getMessage(),
                'domain' => $domain,
                'available' => false,
                'records' => []
            ];
        }
    }

    private function getWhoisInfo(string $domain): array {
        // Try API first if configured
        if ($this->useApi && !empty($this->whoisApiKey)) {
            try {
                $apiResult = $this->getWhoisFromApi($domain);
                if (!isset($apiResult['error'])) {
                    return $apiResult;
                }
            } catch (Exception $e) {
                // API failed, will fall back to native WHOIS
            }
        }

        // Fallback to native WHOIS
        return $this->getNativeWhoisInfo($domain);
    }

    private function getWhoisFromApi(string $domain): array {
        $url = sprintf(
            'https://whois.whoisxmlapi.com/api/v1?apiKey=%s&domainName=%s',
            $this->whoisApiKey,
            urlencode($domain)
        );

        $ctx = stream_context_create([
            'http' => [
                'timeout' => $this->timeout,
                'ignore_errors' => true,
                'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            ]
        ]);

        $response = @file_get_contents($url, false, $ctx);
        if ($response === false) {
            throw new Exception('Failed to fetch WHOIS information from API');
        }

        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Invalid WHOIS API response');
        }

        return [
            'registrar' => $data['registrarName'] ?? 'Unknown',
            'created_date' => $data['createdDate'] ?? 'Unknown',
            'expiry_date' => $data['expiresDate'] ?? 'Unknown',
            'registrant' => [
                'organization' => $data['registrant']['organization'] ?? 'Private',
                'country' => $data['registrant']['country'] ?? 'Unknown'
            ],
            'status' => $data['status'] ?? ['Unknown'],
            'nameservers' => $data['nameServers']['hostNames'] ?? [],
            'source' => 'api'
        ];
    }

    private function getNativeWhoisInfo(string $domain): array {
        try {
            // Create a socket connection to whois server
            $whois_server = 'whois.iana.org';
            $port = 43;
            
            $sock = @fsockopen($whois_server, $port, $errno, $errstr, $this->timeout);
            if (!$sock) {
                throw new Exception("Socket connection failed: $errstr");
            }
            
            // Query the whois server
            fwrite($sock, $domain . "\r\n");
            $whois_data = '';
            while (!feof($sock)) {
                $whois_data .= fgets($sock, 128);
            }
            fclose($sock);
            
            // Parse the WHOIS data
            $info = $this->parseWhoisData($whois_data, $domain);
            
            $result = [
                'registrar' => $info['registrar'] ?? 'Unknown',
                'created_date' => $info['created'] ?? 'Unknown',
                'expiry_date' => $info['expires'] ?? 'Unknown',
                'registrant' => [
                    'organization' => $info['organization'] ?? 'Private',
                    'country' => $info['country'] ?? 'Unknown'
                ],
                'status' => $info['status'] ?? ['Unknown'],
                'nameservers' => $info['nameservers'] ?? [],
                'source' => 'native'
            ];

            return $result;
        } catch (Exception $e) {
            return [
                'error' => 'WHOIS information unavailable',
                'details' => $e->getMessage(),
                'source' => 'native'
            ];
        }
    }

    private function parseWhoisData(string $data, string $domain): array {
        $result = [];
        
        // Common patterns in WHOIS data
        $patterns = [
            'registrar' => '/Registrar:[^\n]*?([\w\s\-,\.]+)/',
            'created' => '/Creation Date:[^\n]*?([\d\-\/: \.]+)/',
            'expires' => '/Registry Expiry Date:[^\n]*?([\d\-\/: \.]+)/',
            'organization' => '/Registrant Organization:[^\n]*?([\w\s\-,\.]+)/',
            'country' => '/Registrant Country:[^\n]*?([\w\s\-,\.]+)/',
            'status' => '/Domain Status:[^\n]*?([\w\s\-,\.]+)/',
            'nameservers' => '/Name Server:[^\n]*?([\w\s\-,\.]+)/'
        ];
        
        // Extract data using patterns
        foreach ($patterns as $key => $pattern) {
            if (preg_match_all($pattern, $data, $matches)) {
                if ($key === 'status' || $key === 'nameservers') {
                    $result[$key] = array_map('trim', $matches[1]);
                } else {
                    $result[$key] = trim($matches[1][0]);
                }
            }
        }
        
        // If IANA refers to another WHOIS server, query it
        if (preg_match('/whois\.[^\n\r]+/', $data, $matches)) {
            $whois_server = trim($matches[0]);
            if ($whois_server !== 'whois.iana.org') {
                $sock = @fsockopen($whois_server, 43, $errno, $errstr, $this->timeout);
                if ($sock) {
                    fwrite($sock, $domain . "\r\n");
                    $secondary_data = '';
                    while (!feof($sock)) {
                        $secondary_data .= fgets($sock, 128);
                    }
                    fclose($sock);
                    
                    // Parse the secondary WHOIS data
                    foreach ($patterns as $key => $pattern) {
                        if (preg_match_all($pattern, $secondary_data, $matches)) {
                            if ($key === 'status' || $key === 'nameservers') {
                                $result[$key] = array_map('trim', $matches[1]);
                            } else {
                                $result[$key] = trim($matches[1][0]);
                            }
                        }
                    }
                }
            }
        }
        
        return $result;
    }    
   
    private function cleanDomain(string $domain): string {
        // Remove whitespace
        $domain = trim($domain);
        
        // Remove http://, https://, www. and trailing slashes
        $domain = preg_replace('#^https?://#', '', $domain);
        $domain = preg_replace('#^www\.#', '', $domain);
        $domain = rtrim($domain, '/');
        $domain = rtrim($domain, '\\');
        
        // Convert to lowercase
        $domain = strtolower($domain);
        
        return $domain;
    }
    
    private function getDnsRecordsSecure(string $domain): array {
        $ctx = stream_context_create([
            'http' => [
                'timeout' => $this->timeout,
                'ignore_errors' => true,
                'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            ]
        ]);
        
        $url = sprintf(
            'https://dns.google/resolve?name=%s&type=ANY',
            urlencode($domain)
        );
        
        $response = @file_get_contents($url, false, $ctx);
        if ($response === false) {
            throw new Exception('Failed to query DNS records');
        }
        
        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Invalid response from DNS server');
        }
        
        return $data['Answer'] ?? [];
    }
    
  
    private function isValidDomain(string $domain): bool {
        return (bool) preg_match(
            '/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/',
            $domain
        );
    }
}

// Handle AJAX requests
if (isset($_GET['domain'])) {
    header('Content-Type: application/json');
    try {
        $checker = new DomainChecker();
        $result = $checker->checkAvailability($_GET['domain']);
        echo json_encode($result);
    } catch (Exception $e) {
        echo json_encode(['error' => 'Server error occurred: ' . $e->getMessage()]);
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Availability Checker</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            display: flex;
            min-height: 100vh;
            align-items: center;
            background-color: #f8f9fa;
        }
        .domain-checker {
            width: 100%;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .result-box {
            margin-top: 20px;
            display: none;
        }
        .dns-records-container {
            display: none;
            margin-top: 15px;
        }
        .btn-toggle-records {
            margin-top: 10px;
        }
        .records-table {
            margin-top: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="domain-checker">
            <h2 class="text-center mb-4">Domain Availability Checker</h2>
            <div class="card">
                <div class="card-body">
                    <form id="domainForm">
                        <div class="input-group mb-3">
                            <input type="text" class="form-control" id="domainInput" 
                                   placeholder="Enter domain name (e.g., example.com)" required>
                            <button class="btn btn-primary" type="submit" id="checkButton">
                                Check Availability
                            </button>
                        </div>
                    </form>
                    
                    <div id="resultBox" class="result-box">
						<div id="statusMessage" class="alert"></div>
						<div id="whoisInfo"></div>
						<div id="dnsButtonContainer" style="display: none;">
							</div>
						<div id="dnsRecords" class="dns-records-container"></div>
						<p id="registrationMessage"></p>
					</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let dnsRecordsVisible = false;
        
        function formatDate(dateStr) {
            if (!dateStr || dateStr === 'Unknown') return 'Unknown';
            try {
                return new Date(dateStr).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                });
            } catch (e) {
                return dateStr; // Return original string if parsing fails
            }
        }
        
        function toggleDnsRecords() {
            const dnsRecords = document.getElementById('dnsRecords');
            const toggleButton = document.querySelector('.btn-toggle-records');
            dnsRecordsVisible = !dnsRecordsVisible;
            
            dnsRecords.style.display = dnsRecordsVisible ? 'block' : 'none';
            toggleButton.textContent = dnsRecordsVisible ? 'Hide DNS Records' : 'Show DNS Records';
        }

        function resetDnsRecordsState() {
            dnsRecordsVisible = false;
            const dnsRecords = document.getElementById('dnsRecords');
            if (dnsRecords) {
                dnsRecords.style.display = 'none';
            }
            const toggleButton = document.querySelector('.btn-toggle-records');
            if (toggleButton) {
                toggleButton.textContent = 'Show DNS Records';
            }
        }

        function formatDomain(domain) {
            return domain.trim()
                      .replace(/^https?:\/\//i, '')
                      .replace(/^www\./i, '')
                      .replace(/[\/\\]+$/, '');
        }

        function displayWhoisInfo(whois) {
            const whoisInfoDiv = document.getElementById('whoisInfo');
            if (!whois || whois.error) {
                whoisInfoDiv.innerHTML = '';
                return;
            }

            whoisInfoDiv.innerHTML = `
                <div class="card mt-3">
                    <div class="card-header">
                        <h5 class="mb-0">Domain Information</h5>
                    </div>
                    <div class="card-body">
                        <dl class="row mb-0">
                            <dt class="col-sm-4">Registrar</dt>
                            <dd class="col-sm-8">${whois.registrar || 'Unknown'}</dd>
                            
                            <dt class="col-sm-4">Registration Date</dt>
                            <dd class="col-sm-8">${formatDate(whois.created_date)}</dd>
                            
                            <dt class="col-sm-4">Expiry Date</dt>
                            <dd class="col-sm-8">${formatDate(whois.expiry_date)}</dd>
                            
                            <dt class="col-sm-4">Registrant</dt>
                            <dd class="col-sm-8">
                                ${whois.registrant.organization || 'Private'}<br>
                                <small class="text-muted">Country: ${whois.registrant.country || 'Unknown'}</small>
                            </dd>
                            
                            <dt class="col-sm-4">Status</dt>
                            <dd class="col-sm-8">${Array.isArray(whois.status) ? 
                                whois.status.join('<br>') : whois.status || 'Unknown'}</dd>
                        </dl>
                    </div>
                </div>
            `;

			if (whois && whois.message) {
				document.getElementById('registrationMessage').innerHTML = whois.message;
			} else {
				document.getElementById('registrationMessage').innerHTML = '';
			}
        }

        function displayDnsRecords(records) {
            const dnsRecordsDiv = document.getElementById('dnsRecords');
            if (!records || !records.length) {
                dnsRecordsDiv.innerHTML = '';
                return;
            }

            dnsRecordsDiv.innerHTML = `
                <table class="table records-table">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Data</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${records.map(record => `
                            <tr>
                                <td>${record.type}</td>
                                <td>${record.data}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }

        document.getElementById('domainForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            let domain = document.getElementById('domainInput').value.trim();
            const button = document.getElementById('checkButton');
            const resultBox = document.getElementById('resultBox');
            const statusMessage = document.getElementById('statusMessage');
            const dnsButtonContainer = document.getElementById('dnsButtonContainer');
            
            domain = formatDomain(domain);
            document.getElementById('domainInput').value = domain;
            
            if (!domain) {
                resultBox.style.display = 'block';
                statusMessage.className = 'alert alert-danger';
                statusMessage.textContent = 'Please enter a domain name';
                dnsButtonContainer.style.display = 'none';
                return;
            }
            
            button.disabled = true;
            button.textContent = 'Checking...';
            resultBox.style.display = 'none';
            dnsButtonContainer.style.display = 'none';
            resetDnsRecordsState();
            
            try {
                const response = await fetch(`?domain=${encodeURIComponent(domain)}`, {
                    headers: { 'Accept': 'application/json' }
                });
                
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    throw new Error('Received non-JSON response from server');
                }
                
                const data = await response.json();
                console.log('Response data:', data);
                
                resultBox.style.display = 'block';
                
                if (data.error) {
                    statusMessage.className = 'alert alert-danger';
                    statusMessage.textContent = data.error;
                    displayWhoisInfo(null);
                    displayDnsRecords(null);
                    dnsButtonContainer.style.display = 'none';
                } else if (data.available) {
                    statusMessage.className = 'alert alert-success';
                    statusMessage.textContent = 'Domain is available!';
                    displayWhoisInfo(null);
                    displayDnsRecords(null);
                    dnsButtonContainer.style.display = 'none';
					    document.getElementById('registrationMessage').innerHTML = data.message || '';
                } else {
                    statusMessage.className = 'alert alert-warning';
                    statusMessage.textContent = 'Domain is already registered.';
                    displayWhoisInfo(data.whois);
                    displayDnsRecords(data.records);
                    dnsButtonContainer.style.display = 'block';
                }
            } catch (error) {
                console.error('Error:', error);
                resultBox.style.display = 'block';
                statusMessage.className = 'alert alert-danger';
                statusMessage.textContent = 'Error checking domain. Please try again.';
                displayWhoisInfo(null);
                displayDnsRecords(null);
                dnsButtonContainer.style.display = 'none';
            } finally {
                button.disabled = false;
                button.textContent = 'Check Availability';
            }
        });
    </script>
</body>

</html>