 param (
    [string]$api_key = $(throw "-api_key is required."),
    [string]$target_gcp_region = $(throw "-target_gcp_region is required."),
    [string]$cluster_name = $(throw "-cluster_name is required."),
    [string]$stack_version = $(throw "-stack_version is required."),
    [string]$snapshot_name,
    [string]$snapshot_src_cluster_id
 )

$elastic_cloud_api_uri = "https://api.elastic-cloud.com/api/v1/deployments"
$elastic_cloud_plan_template = "C:\Elastic\wsplan.json"
$credentials_file_path = "C:\Users\Administrator\Desktop\cluster.txt"

#Update Elastic Cloud Plan based on command line parameters
$elastic_cloud_plan = Get-Content -Raw $elastic_cloud_plan_template | ConvertFrom-JSON
$elastic_cloud_plan.name = $cluster_name
$elastic_cloud_plan.resources[0].elasticsearch[0].region = $target_gcp_region
$elastic_cloud_plan.resources[0].elasticsearch[0].plan.elasticsearch.version = $stack_version
$elastic_cloud_plan.resources[0].kibana[0].plan.kibana.version = $stack_version
if ($snapshot_name) {
    $elastic_cloud_plan.resources[0].elasticsearch[0].plan.transient.restore_snapshot.snapshot_name = $snapshot_name
}
if ($snapshot_src_cluster_id) {
    $elastic_cloud_plan.resources[0].elasticsearch[0].plan.transient.restore_snapshot.source_cluster_id = $snapshot_src_cluster_id
}

$cluster_info = Invoke-RestMethod -Method Post -Uri $elastic_cloud_api_uri `
                                  -Headers @{ 'Authorization' = "ApiKey $api_key"; 'Content-Type' = 'application/json'} `
                                  -Body ($elastic_cloud_plan | ConvertTo-Json -Depth 32)

$cluster_id = $cluster_info.id 
$cloud_id = $cluster_info.resources.cloud_id
$password = $cluster_info.resources.credentials.password

Write-Host -NoNewLine "Elastic Cloud Deployment [$cluster_id] is being created"
do {
    Start-Sleep -Seconds 10
    $cluster = (Invoke-RestMethod -Method Get -Uri $elastic_cloud_api_uri/$cluster_id `
                                  -Headers @{ 'Authorization' = "ApiKey $api_key"; 'Content-Type' = 'application/json'})
    $healthy = $cluster.healthy
    Write-Host -NoNewLine "."
}
until ($healthy -eq $True)
Write-Host "done"

$kibana_url = $cluster.resources.kibana.info.metadata.endpoint
$elasticsearch_url = $cluster.resources[0].elasticsearch[0].info.metadata.endpoint

#Create Credentials File
New-Item -Force $credentials_file_path | Out-Null
Add-Content $credentials_file_path "Kibana URL: https://$kibana_url"
Add-Content $credentials_file_path "Elasticsearch URL: https://$elasticsearch_url"
Add-Content $credentials_file_path "Cloud ID: $cloud_id"
Add-Content $credentials_file_path "Username: elastic"
Add-Content $credentials_file_path "Password: $password"

#Configure Beats
function ElasticBeatSetup ([string]$beat_name)
{
    Write-Host "Setting up $beat_name"
    $beat_exe_path = "C:\Program Files\Elastic\Beats\$stack_version\$beat_name\$beat_name.exe"
    $beat_config_path = "C:\ProgramData\Elastic\Beats\$beat_name\$beat_name.yml"

    # Create Beat Keystore and add CLOUD_ID and ES_PWD keys to it
    $params = $('-c', $beat_config_path, 'keystore','create','--force')
    & $beat_exe_path $params
    $params = $('-c', $beat_config_path, 'keystore','add','CLOUD_ID','--stdin','--force')
    Write-Output $cloud_id | & $beat_exe_path $params
    $params = $('-c', $beat_config_path, 'keystore','add','ES_PWD','--stdin','--force')
    Write-Output $password | & $beat_exe_path $params
    
    # Run Beat Setup
    $params = $('-c', $beat_config_path, 'setup')
    & $beat_exe_path $params
    
    Write-Host "Starting $beat_name Service"
    Start-Service -Name $beat_name
}
ElasticBeatSetup("winlogbeat");
ElasticBeatSetup("packetbeat");

Write-Host "Cluster was successfully created"
