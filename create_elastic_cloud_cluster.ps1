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
$workshop_uri = "https://raw.githubusercontent.com/secops4thewin/elastic-security-workshop/master"
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
& sc.exe failure $beat_name reset=30 actions=restart/5000
}
ElasticBeatSetup("winlogbeat");
ElasticBeatSetup("packetbeat");
ElasticBeatSetup("metricbeat");

Write-Output "`nSetup complete!"



## Create enrollment section for Elastic Agent
Write-Output "Create Authentication Header for Kibana"

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
$bodyMsg = @{"forceRecreate" = "true"}
$bodyJson = ConvertTo-Json($bodyMsg)

Write-Output "Download Pipeline file from $pipeline_file"

## Create index pipelines for Windows Data Collection
# Create Headers for Elasticsearch post Request
$esHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$esHeaders.Add("Content-Type", "application/json")
$esHeaders.Add("Accept", "application/json")
$esHeaders.Add("Authorization", $basicAuthHeader)
$pipelineJson = Invoke-WebRequest -Uri $pipeline_file | ConvertFrom-Json

Write-Output "Create index templates for winlogbeat"

foreach ($pipeline in $pipelineJson){
$pipeline_name = $pipeline.name
$pipelineJsonBody = $pipeline.pipeline.$pipeline_name | ConvertTo-Json -Depth 10
Write-Output "Creating index templates $pipeline_name"
Invoke-RestMethod -Uri "https://$elasticsearch_url/_ingest/pipeline/$pipeline_name" -Method "PUT" -Headers $esHeaders -Body $pipelineJsonBody
}



# Create Fleet User
Write-Output "Create Fleet User"
Write-Output "Creating fleet user at https://$kibana_url/api/fleet/setup"
$fleetCounter = 0
do {
Start-Sleep -Seconds 20
Write-Output "Trying $fleetCounter times"
try{
Write-Output "Creating fleet user with POST request at https://$kibana_url/api/fleet/setup"
Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/fleet/agents/setup" -ContentType "application/json" -Headers $headers -Method POST -body $bodyJson -ErrorAction SilentlyContinue -ErrorVariable SearchError
}
catch{
Write-output "Error Message Array: $searchError"
}
Start-Sleep -Seconds 5
# Checking the content output to see if the host is ready.
try{
Write-Output "Checking if Fleet Manager is ready with GET request https://$kibana_url/api/fleet/enrollment-api-keys?page=1&perPage=20"
$ekIDBody = (Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/fleet/agent_policies?page=1&perPage=20&sortField=updated_at&sortOrder=desc&kuery=" -ContentType "application/json" -Headers $headers -Method GET  -ErrorVariable SearchError)
$isReady = (convertfrom-json($ekIDBody.content)).total
}
catch{
Write-output "Error Message Array: $searchError"
}

$fleetCounter++
}
until (($isReady -gt 0) -or ($fleetCounter -eq 5) )

# Get Body of Fleet Enrollment API Key
Write-Output "Get Enrollment API Key"
$ApiKeyList = (ConvertFrom-Json(Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/fleet/enrollment-api-keys" -ContentType "application/json" -Headers $headers -Method GET))

# Get Fleet TOken from json message
$ApiKeyId = $ApiKeyList.list[0].id

$ApiKeyActual = (ConvertFrom-Json(Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/fleet/enrollment-api-keys/$ApiKeyId" -ContentType "application/json" -Headers $headers -Method GET))
$fleetToken = $ApiKeyActual.item[0].api_key
$policyId = $ApiKeyActual.item[0].policy_id

# Get list of current packages for an up to date Endpoint Version
$packageList = (convertfrom-json(Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/fleet/epm/packages" -ContentType "application/json" -Headers $headers -Method GET))
$endpointPackageVersion = ($packageList.response | where {$_.name -eq "endpoint"}).version

# Create a json request format suitable for  the configuration id
$securityConfigDict = @"
{
"name": "security",
"description": "",
"namespace": "default",
"policy_id": "$policyId",
"enabled": "true",
"output_id": "",
"inputs": [],
"package": {
"name": "endpoint",
"title": "Elastic Endpoint Security",
"version": "$endpointPackageVersion"
}
}

"@ | convertfrom-json

$securityConfigDictJson = ConvertTo-Json($securityConfigDict)

Write-Output "Enable Security Integration into Default Config in Ingest Manager"
Invoke-WebRequest -UseBasicParsing -Uri  "https://$kibana_url/api/fleet/package_policies" -ContentType "application/json" -Headers $headers -Method POST -body $securityConfigDictJson


$elasticAgentUrl = "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$agent_version-windows-x86_64.zip"
$agent_install_folder = "C:\Program Files\Elastic\Agent\"

if (!(Test-Path $agent_install_folder)) {
New-Item -Path $agent_install_folder -Type directory | Out-Null
}
Write-Output "Downloading Elastic Agent"
Invoke-WebRequest -Uri $elasticAgentUrl -OutFile "$install_dir\elastic-agent-$agent_version-windows-x86_64.zip"
Write-Output "Installing Elastic Agent..."
Write-Output "Unzipping Elastic Agent from $install_dir\elastic-agent-$agent_version-windows-x86_64.zip to $agent_install_folder"
Expand-Archive -literalpath $install_dir\elastic-agent-$agent_version-windows-x86_64.zip -DestinationPath $install_dir

# Rename-Item "$agent_install_folder\elastic-agent-$agent_version-windows-x86_64" "$agent_install_folder\Elastic-Agent"
Write-Output "Running enroll process of Elastic Agent with token: $fleetToken at url: https://$kibana_url"
#install -f --kibana-url=KIBANA_URL --enrollment-token=ENROLLMENT_KEY
Start-Process -WorkingDirectory "$install_dir\elastic-agent-$agent_version-windows-x86_64\" -FilePath "elastic-agent" -ArgumentList "install -f --kibana-url=https://$kibana_url  --enrollment-token=$fleetToken" -Wait

Write-Output "Running Agent Install Process"
# & "$agent_install_folder\elastic-agent-$agent_version-windows-x86_64\install-service-elastic-agent.ps1" -Wait

if ((get-service "elastic-agent") -eq "Stopped")
{
Write-Output "Starting Agent Service"

start-service "elastic-agent"
}

# Download Caldera Implant
Write-Output "Downloading Caldera Implant Script"
Invoke-WebRequest -Uri "$workshop_uri/caldera_implant.ps1" -OutFile "C:\Users\Administrator\Desktop\caldera_implant.ps1"

# Download Adversary Emulation Rules
Write-Output "Downloading Workshop Rules"
Invoke-WebRequest -Uri "$workshop_uri/siem_rules/AdversaryEmulation001.ndjson" -OutFile "$install_dir\AdversaryEmulation001.ndjson"
Invoke-WebRequest -Uri "$workshop_uri/siem_rules/AdversaryEmulation002.ndjson" -OutFile "$install_dir\AdversaryEmulation002.ndjson"
Invoke-WebRequest -Uri "$workshop_uri/siem_rules/AdversaryEmulation003.ndjson" -OutFile "$install_dir\AdversaryEmulation003.ndjson"
Invoke-WebRequest -Uri "$workshop_uri/siem_rules/AdversaryEmulation004.ndjson" -OutFile "$install_dir\AdversaryEmulation004.ndjson"

# Enable Siem Signal Rules
Write-Output "Enabling SIEM Rules"
Invoke-RestMethod "https://$kibana_url/api/detection_engine/rules/prepackaged" -Method 'PUT' -Headers $headers -Body $body

# Upload each rule to Elastic
$ruleList = @("$install_dir\AdversaryEmulation001.ndjson", "$install_dir\AdversaryEmulation002.ndjson", "$install_dir\AdversaryEmulation003.ndjson", "$install_dir\AdversaryEmulation004.ndjson")io'k'k'lo'oLK?Ol/lolo;
foreach ($rule in $ruleList)
{
Write-Output "Adding Rule $rule"
$multipartContent = [System.Net.Http.MultipartFormDataContent]::new()
$multipartFile = $rule
$FileStream = [System.IO.FileStream]::new($multipartFile, [System.IO.FileMode]::Open)
$fileHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
$fileHeader.Name = "file"
$fileHeader.FileName = "AdversaryEmulation001.ndjson"
$fileContent = [System.Net.Http.StreamContent]::new($FileStream)
$fileContent.Headers.ContentDisposition = $fileHeader
$multipartContent.Add($fileContent)

$body = $multipartContent

$response = Invoke-RestMethod "https://$kibana_url/api/detection_engine/rules/_import" -Method 'POST' -Headers $headers -Body $body
}

New-Item -Force $done_file_path | Out-Null
Write-Output "Finished"

Add-Content $done_file_path "Done"
