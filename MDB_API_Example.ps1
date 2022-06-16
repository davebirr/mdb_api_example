#appID and secret registered in your partner tenant. Note, for production purposes do not store the secret
#as plan text.  Either use secure strings and save to local file system or something like Azure Key Vault
#$secret = Read-Host -AsSecureString


$appId = ""
$secret = ""

#Class to contain customer tenants
Class tenant{
    [string] $tenantId;
    [string] $domain;
    [string] $name;
    [string] $appId;
    [string] $appSecret;
    [string] $token;
    [System.Collections.ArrayList]$machines = @()
    [System.Collections.ArrayList]$vulnerabilities = @()
    tenant([string]$tenantIdIn, [string]$domainIn, [string]$nameIn, [string]$appIdIn, [string]$appSecretIn) {
        $this.name = $nameIn
        $this.domain = $domainIn
        $this.tenantId = $tenantIdIn
        $this.appId = $appIdIn
        $this.appSecret = $appSecretIn
    }
    [void] getToken(){
        # That code gets the App Context Token and saves it to a variable inside the class
        $resourceAppIdUri = "https://api.securitycenter.microsoft.com"
        $oAuthUri = "https://login.microsoftonline.com", $this.tenantId, "oauth2/token" -join "/"
        $authBody = [Ordered] @{
             resource = $resourceAppIdUri
             client_id = $($this.appId)
             client_secret = $($this.appSecret)
             grant_type = 'client_credentials'
        }
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
        $this.token = $authResponse.access_token
    }
    [string] getAlerts([int]$hours=48){
    # Returns Alerts created in the specified hours prior, 48 by default

    $dateTime = (Get-Date).ToUniversalTime().AddHours(-$hours).ToString("o")

    # The URL contains the type of query and the time filter we create above
    $url = "https://api.securitycenter.microsoft.com/api/alerts?`$filter=alertCreationTime ge $dateTime"

    # Set the WebRequest headers
    $headers = @{
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $($this.token)"
    }

    # Send the webrequest and get the results.
    $response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop

    # Extract the alerts from the results.
    #$alerts =  ($response | ConvertFrom-Json).value | ConvertTo-Json
    $alerts = ($response | ConvertFrom-Json).value

    # Get string with the execution time. We concatenate that string to the output file to avoid overwrite the file
    $dateTimeForFileName = Get-Date -Format o | foreach {$_ -replace ":", "."}

    # Send the result back
    return $alerts
    }
    [void] getVulnerabilities() {
    $url = "https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities"

    # Set the WebRequest headers
    $headers = @{
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $($this.token)"
    }

    # Send the webrequest and get the results.
    $response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop
    
    $this.vulnerabilities = ($response.content | ConvertFrom-Json).value
    
    # Send the result back
    #return $vulnerabilities

    }
    [void] getMachines() {
    $url = "https://api.securitycenter.microsoft.com/api/machines"

    # Set the WebRequest headers
    $headers = @{
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $($this.token)"
    }

    # Send the webrequest and get the results.
    $response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop

    $this.machines = ($response.content | ConvertFrom-Json).value

    # Send the result back
    #return $machines
    
    }
}

#Class to hold partner tenant details as well as an array of customer tenants
Class partner{
    [string] $partnerTenantId;
    [string] $appId;
    [string] $appSecret;
    [System.Collections.ArrayList]$customerTenants = @()
    partner ([string]$tenantIdIn, [string]$appIdIn, [string]$appSecretIn) {
    $this.partnerTenantId = $tenantIdIn
    $this.appId = $appIdIn
    $this.appSecret = $appSecretIn
    }
    [void]addCustomer([string]$CustomerId, [string]$domain, [string]$name) {
        #$newCustomerNumber = $this.GetNewCUstomerNumber()
        $newCustomer = [tenant]::new($CustomerId, $domain, $name, $this.appId, $this.appSecret)

        $this.customerTenants.Add($newCustomer)
    }
    [string]consentLink() {
        return "https://login.microsoftonline.com/common/oauth2/authorize?prompt=consent",
        "client_Id=$this.appId","response_type=code","sso_reload=true" -join "&"
    }
}

#Install PartnerCenter Module. This only needs to be done once (with elevated permissions)
Install-Module PartnerCenter

#Connect interactively to Partner Center using MFA
$pcConnection = Connect-PartnerCenter

#Create a partner object with my partner details. This will also hold customer tenant objects
$myPartnerTenant = [partner]::new($pcConnection.Account.Tenant, $appId, $secret)

#Copy consent link to the clipboard to email to customers or provide direct admin consent in customer tenants
Set-Clipboard $myPartnerTenant.consentlink()

#Get a list of all customers from Partner Center
$myCustomers = Get-PartnerCustomer

#Add all of the customers to my partner tenant object
foreach ($customer in $myCustomers) {
$myPartnerTenant.addCustomer($customer.CustomerId, $customer.Domain, $customer.Name)
}

#Example walk through for a single customer tenant.  In this example we're picking the 5th tenant in the ArrayList
$id = 4

#Get an authorization token for this customer tenant and store it
$myPartnerTenant.customerTenants[$id].getToken()

#Retrieve the machines and vulnerabilities for the customer tenant using the API
$myPartnerTenant.customerTenants[$id].getMachines()
$myPartnerTenant.customerTenants[$id].getVulnerabilities()

#Get the machines in the tenant so we can correlate data in vulnerabilities with more meaningful info such as computer dns name
$machines = $myPartnerTenant.customerTenants[$id].machines | group -AsHashTable -Property id

#Here a look at some raw vulnerability data. It's much more helpful if we correlate machineID to computer names and format this for readability
$myPartnerTenant.customerTenants[$id].vulnerabilities | select -first 3

#Fomat the raw data into something useful
#CSS codes
$header = @"
<style>
    h1 {
        font-family: Arial, Helvetica, sans-serif;
        color: #e68a00;
        font-size: 28px;
    }
 
    h2 {
        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;
    }

   table {
		font-size: 12px;
		border: 0px; 
		font-family: Arial, Helvetica, sans-serif;
	} 
	
    td {
		padding: 4px;
		margin: 0px;
		border: 0;
	}
	
    th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
	}
    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }
    #CreationDate {

        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;
    }
    .StopStatus {

        color: #ff0000;
    }
    .RunningStatus {

        color: #008000;
    }
</style>
"@

#The command below will get the name of the customer
$CustomerName = "<h1>Customer name: $($myPartnerTenant.customerTenants[$id].Name)</h1>"

#The command below will get the Vulnerability SUmmary, convert the result to HTML code as table and store it to a variable
$VulnerabilitySummary = $myPartnerTenant.customerTenants[$id].vulnerabilities | Sort-Object Severity | Group-Object severity | ConvertTo-Html -As List -Property Name,Count -Fragment -PreContent "<h2>Vulnerability Summary Information</h2>"

#The command below will get the Vulnerability Summary by machiens & severity, convert the result to HTML code as table and store it to a variable
#$MachineSummary = $myPartnerTenant.customerTenants[$id].vulnerabilities | Group-Object machineId,severity | Select-Object @{n="ComputerName";e={$machines[$_.Values[0]].computerdnsname}},@{n="Severity";e={$_.Values[1]}},Count | ConvertTo-Html -As List -Property ComputerName,Severity,Count -Fragment -PreContent "<h2>Vulnerability Count by Machine & Severity</h2>"
$MachineSummary = $myPartnerTenant.customerTenants[$id].vulnerabilities | Sort-Object Severity | Group-Object machineId,severity | Select-Object @{n="ComputerName";e={$machines[$_.Values[0]].computerdnsname}},@{n="Severity";e={$_.Values[1]}},Count | ConvertTo-Html -Property ComputerName,Severity,Count -Fragment -PreContent "<h2>Vulnerability Count by Machine & Severity</h2>"

#The command below will get vulnerability detail, convert the result to HTML code as table and store it to a variable
$CriticalVulnerabilities = $myPartnerTenant.customerTenants[$id].vulnerabilities | ? {$_.Severity -eq "Critical"} | Sort-Object cveId | Select-Object Severity, cveId, @{n="ComputerName";e={$machines[$_.machineId].computerdnsname}}  |ConvertTo-Html -Property Severity,cveId,ComputerName -Fragment -PreContent "<h2>Critical Severity Vulnerability Detail Information</h2>"

#The command below will get vulnerability detail, convert the result to HTML code as table and store it to a variable
$HighVulnerabilities = $myPartnerTenant.customerTenants[$id].vulnerabilities | ? {$_.Severity -eq "High"} | Sort-Object cveId | Select-Object Severity, cveId, @{n="ComputerName";e={$machines[$_.machineId].computerdnsname}}  |ConvertTo-Html -Property Severity,cveId,ComputerName -Fragment -PreContent "<h2>High Severity Vulnerability Detail Information</h2>"

#The command below will get vulnerability detail, convert the result to HTML code as table and store it to a variable
$MediumVulnerabilities = $myPartnerTenant.customerTenants[$id].vulnerabilities | ? {$_.Severity -eq "Medium"} | Sort-Object cveId | Select-Object Severity, cveId, @{n="ComputerName";e={$machines[$_.machineId].computerdnsname}}  |ConvertTo-Html -Property Severity,cveId,ComputerName -Fragment -PreContent "<h2>Medium Severity Vulnerability Detail Information</h2>"

#The command below will get vulnerability detail, convert the result to HTML code as table and store it to a variable
$LowVulnerabilities = $myPartnerTenant.customerTenants[$id].vulnerabilities | ? {$_.Severity -eq "Low"} | Sort-Object cveId | Select-Object Severity, cveId, @{n="ComputerName";e={$machines[$_.machineId].computerdnsname}}  |ConvertTo-Html -Property Severity,cveId,ComputerName -Fragment -PreContent "<h2>Low Severity Vulnerability Detail Information</h2>"
  
#The command below will combine all the information gathered into a single HTML report
$Report = ConvertTo-HTML -Body "$CustomerName $VulnerabilitySummary $MachineSummary $CriticalVulnerabilities $HighVulnerabilities $MediumVulnerabilities $LowVulnerabilities" -Head $header -Title "Computer Vulnerability Report" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>"

#The command below will generate the report to an HTML file

$Report | Out-File .\MDB-API-Vulnerability-Report.html
Start-Process "file:///C:/Users/davidb/demos/MDB-API-Vulnerability-Report.html"

