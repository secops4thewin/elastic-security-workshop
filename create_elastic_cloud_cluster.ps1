param (
    [string]$api_key = $(throw "-api_key is required."),
    [string]$target_gcp_region = $(throw "-target_gcp_region is required."),
    [string]$cluster_name = $(throw "-cluster_name is required."),
    [string]$stack_version = $(throw "-stack_version is required.")
 )

 ## Start Cluster Deployment section

$date = (Get-Date).ToString('yyyy-MM-dd')
$cluster_name = "$date`_$cluster_name"
$install_dir = "C:\Elastic"
$elastic_cloud_api_uri = "https://api.elastic-cloud.com/api/v1/deployments"
$elastic_cloud_plan_template = "C:\Elastic\wsplan.json"
$credentials_file_path = "C:\Users\Administrator\Desktop\cluster.txt"
$beat_config_repository_uri = "https://raw.githubusercontent.com/ElasticSA/elastic-security-workshop/v1.0"

Write-Output "*** Adversary Emulation Workshop Setup ***`n"

#Install Sysmon
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$sysmon_installer_uri = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmon_config_uri = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
$sysmon_local_rules_filepath = "C:\Windows\sysmon.xml"
if (Test-Path "C:\Windows\Sysmon64.exe")
{
    Write-Output "Unistalling Sysmon..."
    Start-Process -WorkingDirectory "C:\Windows" -FilePath "sysmon64" -ArgumentList "-u" -Wait
}
Write-Output "Installing Sysmon..."
$sysmon_tmp_dir = "$install_dir\sysmon"
if (!(Test-Path $sysmon_tmp_dir)) {
    New-Item -Path $sysmon_tmp_dir -Type directory | Out-Null
}
Invoke-WebRequest -Uri $sysmon_config_uri -OutFile $sysmon_local_rules_filepath
Invoke-WebRequest -Uri $sysmon_installer_uri -OutFile $sysmon_tmp_dir/Sysmon.zip
Expand-Archive -Path $sysmon_tmp_dir/Sysmon.zip -DestinationPath $sysmon_tmp_dir
Start-Process -WorkingDirectory $sysmon_tmp_dir -FilePath "sysmon64" -ArgumentList "-accepteula -i $sysmon_local_rules_filepath" -Wait -NoNewWindow
Remove-Item -Path $sysmon_tmp_dir -Recurse -Force
Write-Output "Sysmon Installation Complete"

#Download Elastic Cloud Deployment Plan
Write-Output "`nDownloading Elastic Cloud Deployment Plan..."
Invoke-WebRequest -Uri "$beat_config_repository_uri/wsplan.json" -OutFile "$install_dir\wsplan.json"    


#Update Elastic Cloud Plan based on command line parameters
$elastic_cloud_plan = Get-Content -Raw $elastic_cloud_plan_template | ConvertFrom-JSON
$elastic_cloud_plan.name = $cluster_name
$elastic_cloud_plan.resources[0].elasticsearch[0].region = $target_gcp_region
$elastic_cloud_plan.resources[0].elasticsearch[0].plan.elasticsearch.version = $stack_version
$elastic_cloud_plan.resources[0].kibana[0].plan.kibana.version = $stack_version

$cluster_info = Invoke-RestMethod -Method Post -Uri $elastic_cloud_api_uri `
                                  -Headers @{ 'Authorization' = "ApiKey $api_key"; 'Content-Type' = 'application/json'} `
                                  -Body ($elastic_cloud_plan | ConvertTo-Json -Depth 32)

$cluster_id = $cluster_info.id 
$cloud_id = $cluster_info.resources.cloud_id
$password = $cluster_info.resources.credentials.password

Write-Output "Elastic Cloud Deployment [$cluster_id] is being created"
do {
    Start-Sleep -Seconds 10
    $cluster = (Invoke-RestMethod -Method Get -Uri $elastic_cloud_api_uri/$cluster_id `
                                  -Headers @{ 'Authorization' = "ApiKey $api_key"; 'Content-Type' = 'application/json'})
    $healthy = $cluster.healthy
    Write-Host -NoNewLine "."
}
until ($healthy -eq $True)
Write-Output "`nElastic Cloud Deployment was created successfully!"

$kibana_url = $cluster.resources.kibana.info.metadata.endpoint
$elasticsearch_url = $cluster.resources[0].elasticsearch[0].info.metadata.endpoint

#Create Credentials File
New-Item -Force $credentials_file_path | Out-Null
Add-Content $credentials_file_path "Kibana URL: https://$kibana_url"
Add-Content $credentials_file_path "Elasticsearch URL: https://$elasticsearch_url"
Add-Content $credentials_file_path "Cloud ID: $cloud_id"
Add-Content $credentials_file_path "Username: elastic"
Add-Content $credentials_file_path "Password: $password"

#Uninstall all Elastic Beats already installed
$app = Get-WmiObject -Class Win32_Product -Filter ("Vendor = 'Elastic'")
if ($null -ne $app) {
    $app.Uninstall()
}

#Configure Beats
function ElasticBeatSetup ([string]$beat_name)
{
    Write-Output "`n*** Setting up $beat_name ****"
    $beat_install_folder = "C:\Program Files\Elastic\Beats\$stack_version\$beat_name"
    $beat_exe_path = "$beat_install_folder\$beat_name.exe"
    $beat_config_path = "C:\ProgramData\Elastic\Beats\$beat_name\$beat_name.yml"
    $beat_data_path = "C:\ProgramData\Elastic\Beats\$beat_name\data"
    $beat_config_file = "$beat_config_repository_url/$beatname.yml"
    $beat_artifact_uri = "https://artifacts.elastic.co/downloads/beats/$beat_name/$beat_name-$stack_version-windows-x86_64.msi"
    $log_file_path = "$install_dir\$beat_name.log"

    Write-Output "Installing $beat_name..."
    Invoke-WebRequest -Uri "$beat_artifact_uri" -OutFile "$install_dir\$beat_name-$stack_version-windows-x86_64.msi"
    $MSIArguments = @(
        "/i"
        "$install_dir\$beat_name-$stack_version-windows-x86_64.msi"
        "/qn"
        "/norestart"
        "/L"
        $log_file_path
    )
    Start-Process msiexec.exe -Wait -ArgumentList $MSIArguments -NoNewWindow

    #Download Beat configuration file
    Invoke-WebRequest -Uri "$beat_config_repository_uri/$beat_name.yml" -OutFile $beat_config_path

    # Create Beat Keystore and add CLOUD_ID and ES_PWD keys to it
    $params = $('-c', $beat_config_path, 'keystore','create','--force')
    & $beat_exe_path @params
    $params = $('-c', $beat_config_path, 'keystore','add','CLOUD_ID','--stdin','--force','-path.data', $beat_data_path)
    Write-Output $cloud_id | & $beat_exe_path @params
    $params = $('-c', $beat_config_path, 'keystore','add','ES_PWD','--stdin','--force','-path.data', $beat_data_path)
    Write-Output $password | & $beat_exe_path @params
    
    # Run Beat Setup
    Write-Output "Running $beat_name setup..."
    $params = $('-c', $beat_config_path, 'setup', '-path.data', $beat_data_path)
    & $beat_exe_path @params

    Write-Output "Starting $beat_name Service"
    Start-Service -Name $beat_name
}
ElasticBeatSetup("winlogbeat");
ElasticBeatSetup("packetbeat");
ElasticBeatSetup("metricbeat");

Write-Output "`nSetup complete!"



## Create enrollment section for Elastic Agent

# Build authentication information for later requests
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$user = "elastic"
$credential = "${user}:${password}"
$credentialBytes = [System.Text.Encoding]::ASCII.GetBytes($credential)
$base64Credential = [System.Convert]::ToBase64String($credentialBytes)
$basicAuthHeader = "Basic $base64Credential"
$headers = @{
    "Authorization" = $basicAuthHeader;
    "kbn-xsrf" = "reporting"
}

$bodyMsg = @{"forceRecreate" = "false"}
$bodyJson = ConvertTo-Json($bodyMsg)

# Create Fleet User
Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/ingest_manager/fleet/setup" -ContentType "application/json" -Headers $headers -Method POST -body $bodyJson

# Get the first enrollment key
$ekIDBody = (Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/ingest_manager/fleet/enrollment-api-keys?page=1&perPage=20" -ContentType "application/json" -Headers $headers -Method GET)

# Convert the the Enrollment key request body from json and extract the ID to use in the api request.
$ekID= (convertfrom-json($ekIDBody.content))[0].list.id

# Get Body of Fleet Enrollment API Key
$fleetTokenBody = (Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/ingest_manager/fleet/enrollment-api-keys/$ekId" -ContentType "application/json" -Headers $headers -Method GET)

# Get Fleet TOken from json message
$fleetToken = (ConvertFrom-Json($fleetTokenBody.Content)).item.api_key

# Retrieve configuration ID for passing into the following request
$configId = (ConvertFrom-Json($fleetTokenBody.Content)).item.config_id

# Create a json request format suitable for  the configuration id 
$securityConfigDict = @"
{
    "name": "security",
    "description": "",
    "namespace": "default",
    "config_id": "test",
    "enabled": "true",
    "output_id": "",
    "inputs": [],
    "package": {
        "name": "endpoint",
        "title": "Elastic Endpoint Security",
        "version": "0.13.1"
    }
}
"@ | convertfrom-json

$securityConfigDict.config_id = $configId

$securityConfigDictJson = ConvertTo-Json($securityConfigDict)

Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/ingest_manager/package_configs" -ContentType "application/json" -Headers $headers -Method POST -body $securityConfigDictJson
