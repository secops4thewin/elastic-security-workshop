param (
    [string]$api_key = $(throw "-api_key is required."),
    [string]$target_gcp_region = $(throw "-target_gcp_region is required."),
    [string]$cluster_name = $(throw "-cluster_name is required."),
    [string]$stack_version = $(throw "-stack_version is required."),
    [string]$agent_version = $(throw "-agent_version is required.")
 )

 ## Start Cluster Deployment section

$date = (Get-Date).ToString('yyyy-MM-dd')
$cluster_name = "$date`_$cluster_name"
$install_dir = "C:\Elastic"
$elastic_cloud_api_uri = "https://api.elastic-cloud.com/api/v1/deployments"
$elastic_cloud_plan_template = "C:\Elastic\wsplan.json"
$credentials_file_path = "C:\Users\Administrator\Desktop\cluster.txt"
$done_file_path = "C:\Users\Administrator\Desktop\done.txt"
$beat_config_repository_uri = "https://raw.githubusercontent.com/ElasticSA/elastic-security-workshop/v1.0"
$wsplan_config_respository_uri = "https://raw.githubusercontent.com/secops4thewin/elastic-security-workshop/master"
$pipeline_file = "https://raw.githubusercontent.com/secops4thewin/elastic-security-workshop/master/pipelines.json"

Write-Output "*** Adversary Emulation Workshop Setup ***`n"

#Install Sysmon
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$sysmon_installer_uri = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmon_config_uri = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
$sysmon_local_rules_filepath = "C:\Windows\sysmon.xml"

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
Invoke-WebRequest -Uri "$wsplan_config_respository_uri/wsplan.json" -OutFile "$install_dir\wsplan.json"    


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

Write-Output "Creating Credential File"
#Create Credentials File
New-Item -Force $credentials_file_path | Out-Null
Add-Content $credentials_file_path "Kibana URL: https://$kibana_url"
Add-Content $credentials_file_path "Elasticsearch URL: https://$elasticsearch_url"
Add-Content $credentials_file_path "Cloud ID: $cloud_id"
Add-Content $credentials_file_path "Username: elastic"
Add-Content $credentials_file_path "Password: $password"

Write-Output "Uninstalling existing beats"
#Uninstall all Elastic Beats already installed
$app = Get-WmiObject -Class Win32_Product -Filter ("Vendor = 'Elastic'")
if ($null -ne $app) {
    $app.Uninstall()
}

#Configure Beats
function ElasticBeatSetup ([string]$beat_name)
{
    Write-Output "`n*** Setting up $beat_name ****"
    $beat_install_folder = "C:\Program Files\Elastic\Beats\$agent_version\$beat_name"
    $beat_exe_path = "$beat_install_folder\$beat_name.exe"
    $beat_config_path = "C:\ProgramData\Elastic\Beats\$beat_name\$beat_name.yml"
    $beat_data_path = "C:\ProgramData\Elastic\Beats\$beat_name\data"
    $beat_config_file = "$beat_config_repository_url/$beatname.yml"
    $beat_artifact_uri = "https://artifacts.elastic.co/downloads/beats/$beat_name/$beat_name-$agent_version-windows-x86_64.msi"
    $log_file_path = "$install_dir\$beat_name.log"

    Write-Output "Installing $beat_name..."
    Invoke-WebRequest -Uri "$beat_artifact_uri" -OutFile "$install_dir\$beat_name-$agent_version-windows-x86_64.msi"
    $MSIArguments = @(
        "/i"
        "$install_dir\$beat_name-$agent_version-windows-x86_64.msi"
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
Write-Output "Create enrollment section for Elastic Agent"
Start-Sleep -Seconds 60

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

## Create index pipelines for Windows Data Collection
# Create Headers for Elasticsearch post Request
$esHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$esHeaders.Add("Content-Type", "application/json")
$esHeaders.Add("Accept", "application/json")
$esHeaders.Add("Authorization", $basicAuthHeader)
$pipelineJson = Invoke-WebRequest -Uri $pipeline_file | ConvertFrom-Json

foreach ($pipeline in $pipelineJson){
$pipeline_name = $pipeline.name
$pipelineJsonBody = $pipeline.pipeline.$pipeline_name | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri "$elasticsearch_url/_ingest/pipeline/$pipeline_name" -Method "PUT" -Headers $esHeaders -Body $pipelineJsonBody
}

$bodyMsg = @{"forceRecreate" = "false"}
$bodyJson = ConvertTo-Json($bodyMsg)

# Create Fleet User

Write-Output "Create Fleet User"
Write-Output "Creating fleet user at https://$kibana_url/api/fleet/setup"
$fleetCounter = 0
do {
    Start-Sleep -Seconds 20
    Write-Output "Trying $fleetCounter times"
    try{
        Write-Output "Creating fleet user with POST request at https://$kibana_url/api/fleet/setup"
    Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/fleet/setup" -ContentType "application/json" -Headers $headers -Method POST -body $bodyJson -ErrorAction SilentlyContinue -ErrorVariable SearchError
    }
    catch{
        Write-output "Error Message Array: $searchError"
    }
    Start-Sleep -Seconds 5
    # Checking the content output to see if the host is ready.
    try{
    Write-Output "Checking if Fleet Manager is ready with GET request https://$kibana_url/api/fleet/setup"
    $fleetGet =  Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/fleet/check-permissions" -ContentType "application/json" -Headers $headers -Method GET -ErrorVariable SearchError
    $isReady = (convertfrom-json($fleetGet).content).success
    }
    catch{
        Write-output "Error Message Array: $searchError"
    }
    
    $fleetCounter++
}
until (($isReady -eq $True) -or ($fleetCounter -eq 5) )


# Get the first enrollment key
Write-Output "Get first enrollment key"
$ekIDBody = (Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/fleet/enrollment-api-keys?page=1&perPage=20" -ContentType "application/json" -Headers $headers -Method GET)

# Convert the the Enrollment key request body from json and extract the ID to use in the api request.
$ekID= (convertfrom-json($ekIDBody.content))[0].list.id

# Get Body of Fleet Enrollment API Key
Write-Output "Get Enrollment API Key"
$fleetTokenBody = (Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/fleet/enrollment-api-keys/$ekId" -ContentType "application/json" -Headers $headers -Method GET)

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

Write-Output "Enable Security Integration into Default Config in Ingest Manager"
Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/package_configs" -ContentType "application/json" -Headers $headers -Method POST -body $securityConfigDictJson


$elasticAgentUrl = "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$agent_version-windows-x86_64.zip"
$agent_install_folder = "C:\Program Files\Elastic\Agent\$agent_version\"

if (!(Test-Path $agent_install_folder)) {
    New-Item -Path $agent_install_folder -Type directory | Out-Null
}
Write-Output "Downloading Elastic Agent"
Invoke-WebRequest -Uri $elasticAgentUrl -OutFile "$install_dir\elastic-agent-$agent_version-windows-x86_64.zip"
Write-Output "Installing Elastic Agent..."
Write-Output "Unzipping Elastic Agent from $install_dir\elastic-agent-$agent_version-windows-x86_64.zip to $agent_install_folder"
Expand-Archive -literalpath $install_dir\elastic-agent-$agent_version-windows-x86_64.zip -DestinationPath $agent_install_folder

Write-Output "Running enroll process of Elastic Agent with token: $fleetToken at url: https://$kibana_url"
Start-Process -WorkingDirectory "$agent_install_folder\elastic-agent-$agent_version-windows-x86_64\" -FilePath "elastic-agent" -ArgumentList "enroll https://$kibana_url $fleetToken --force" -Wait

Write-Output "Running Agent Install Process"
& "$agent_install_folder\elastic-agent-$agent_version-windows-x86_64\install-service-elastic-agent.ps1" -Wait

if ((get-service "elastic-agent") -eq "Stopped")
{
    start-service "elastic-agent"
}

New-Item -Force $done_file_path | Out-Null
Add-Content $done_file_path "Done"
