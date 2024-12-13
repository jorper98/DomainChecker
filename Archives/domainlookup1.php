<!DOCTYPE html>
<html lang="en">
<head>
    <title>Instant PHP Domain Availability Checker Script</title>
    
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.min.css" integrity="sha384-rwoIResjU2yc3z8GV/NPeZWAv56rSmLldC3R/AZzGRnGxQQKnKkoFVhFQhNUwEyJ" crossorigin="anonymous">

</head>

<body>
    <div class="wrapper">
        <h2>Check Domain Name Availability</h2>
        <div class="container">
            <form action="" method="GET">
                <input id="searchBar" class="searchbar" type="text" name="domain" placeholder="Search domain name..." value="<?php if(isset($_GET['domain'])){ echo $_GET['domain']; } ?>">
                <button type="submit" id="btnSearch" class="btn-search"><i class="fa fa-search"></i></button>
            </form>
        </div>
        <?php
        error_reporting(0);
         function get_dns_records($domain) {
            $dns_records = dns_get_record($domain, DNS_ANY);
            return $dns_records;
        }
        
        
        function get_dns_records_google($domain) {
            $dns_records = [];
            $dns_over_https_url = "https://dns.google/resolve?name=" . urlencode($domain);
            $response = file_get_contents($dns_over_https_url);
            if ($response) {
                $data = json_decode($response, true);
                if (isset($data['Answer'])) {
                    $dns_records = $data['Answer'];
                }
            }
            return $dns_records;
        }
        
        
        if(isset($_GET['domain'])){
            $domain = $_GET['domain'];
            if (gethostbyname($domain) != $domain) {
                echo "<h3 class='fail'>Domain Already Registered!</h3>";
                echo " <br><Br><center>";
                echo "<h3><a href='https://$domain' style='color: green;'>Link to the Domain</a></h3><br>";
                echo "<button type='button' class='btn btn-info' data-toggle='modal' data-target='#myModal'>Show DNS Records</button>";
                echo "<div id='myModal' class='modal fade' role='dialog'>";
                echo "<div class='modal-dialog'>";
                echo "<div class='modal-content'>";
                
                echo "<div class='modal-header'>";
                echo "<button type='button' class='close' data-dismiss='modal'>&times;</button>";
                echo "<h4 class='modal-title'>DNS Records for $domain</h4>";
                echo "</div>";
                echo "<div class='modal-body'>";
                
                echo "<textarea rows='25' cols='50' readonly>";
                
                echo "Domain: $domain\n";
                echo "Status: Taken\n";
                
                echo "Link: https://$domain\n";
                
                $records = get_dns_records($domain);
                
                $records = get_dns_records_google($domain);
                
                foreach ($records as $record) {
                    // echo "{$record['type']}: {$record['target']}\n>";
                    echo "{$record['type']}: {$record['data']}\n";
                }
                
                            echo "=================\n\n\n";
                echo "<table class='table'>";
                echo "<thead><tr><th>Record Type</th><th>Data</th></tr></thead>";
                echo "<tbody>";
                $records = get_dns_records_google($domain);
                foreach ($records as $record) {
                    echo "<tr><td>{$record['type']}</td><td>{$record['data']}</td></tr>";
                }
                echo "</tbody>";
                echo "</table>";
                
                
                echo "</textarea>";
                

                
                echo "</div>";
                                
                echo "</div>";
                echo " <br><Br></center>";
                echo "</div>";
                echo "</div>";
            } else {
                echo "<h3 class='success'>Domain is available! You can register it.</h3>";
            }
        }
        ?>
    </div>
    
    
    <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.2/css/all.css"/>
    <style type="text/css">
        body, h2, h3 {
            font-weight: normal;
            font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
            color: #333;
        }
        body {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 90vh;
        }
        h2 {
            font-size: 26px;
            text-align: center;
        }
        h3 {
            font-size: 24px;
        }
        h3.success {
            color: #008000;
            text-align: center;
        }
        h3.fail {
            color: #ff0000;
            text-align: center;
        }
        .container {
            display: flex;
            flex-direction: row;
            justify-content: center;
            align-items: center;
        }
        .searchbar {
            padding: 6px 10px;
            width: 400px;
            max-width: 100%;
            border: none;
            margin-top: 1px;
            margin-right: 8px;
            font-size: 1em;
            border-bottom: #333 solid 2px;
            transition: 0.3s;
        }
        .searchbar::placeholder {
            font-size: 1em;
        }
        .searchbar:focus {
            outline: none;
        }
        .btn-search {
            cursor: pointer;
            text-decoration: none !important;
            font-size: 1.5em;
            padding-top: 5px;
            padding-bottom: 5px;
            background-color: transparent;
            border: none;
            outline: none;
        }
    </style>
    
    
   <!-- jQuery -->
<script src="https://code.jquery.com/jquery-3.1.1.slim.min.js" integrity="sha384-A7FZj7v+d/sdmMqp/nOQwliLvUsJfDHW+k9Omg/a/EheAdgtzNs3hpfag6Ed950n" crossorigin="anonymous"></script>
<!-- Popper.js -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/tether/1.4.0/js/tether.min.js" integrity="sha384-DztdAPBWPRXSA/3eYEEUWrWCy7G5KFbe8fFjk5JAIxUYHKkDx6Qin1DkWx51bBrb" crossorigin="anonymous"></script>
<!-- Bootstrap JS -->
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/js/bootstrap.min.js" integrity="sha384-vBWWzlZJ8ea9aCX4pEW3rVHjgjt7zpkNpZk+02D9phzyeVkE+jo0ieGizqPLForn" crossorigin="anonymous"></script>

    
    
</body>
</html>
