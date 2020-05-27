param (
    [string]$elastic_cloud_api_key = $(throw "-elastic_cloud_api_key is required."),
    [string]$elastic_cloud_target_region = $(throw "-elastic_cloud_target_region is required."),   
    [string]$stack_version = $(throw "-stack_version is required."),
    [string]$cluster_name = $(throw "-cluster_name is required.")
)

$elastic_cloud_api_uri = "https://api.elastic-cloud.com/api/v1/deployments"
$elastic_cloud_plan_template = "C:\Users\matteo\Elastic\Security Workshop\cluster_plan.json"
$credentials_file_path = "C:\Users\Matteo\Desktop\cluster.txt"
$beats_configs_path = "C:\Users\Matteo\Downloads\Beat Configs"

$elastic_cloud_plan = Get-Content -Raw $elastic_cloud_plan_template | ConvertFrom-JSON
$elastic_cloud_plan.name = $cluster_name
$elastic_cloud_plan.resources[0].elasticsearch[0].plan.elasticsearch.version = $stack_version
$elastic_cloud_plan.resources[0].kibana[0].plan.kibana.version = $stack_version
$elastic_cloud_plan.resources[0].elasticsearch[0].region = $elastic_cloud_target_region

$cluster_info = Invoke-RestMethod -Method Post -Uri "$elastic_cloud_api_uri" `
                                  -Headers @{ 'Authorization' = "ApiKey $elastic_cloud_api_key"; 'Content-Type' = 'application/json'} `
                                  -Body ($elastic_cloud_plan | ConvertTo-Json -Depth 32)

$cluster_id = $cluster_info.id 
$cloud_id = $cluster_info.resources.cloud_id
$password = $cluster_info.resources.credentials.password

do {
    Start-Sleep -Seconds 5
    $cluster = (Invoke-RestMethod -Method Get -Uri $elastic_cloud_api_uri/$cluster_id `
                                  -Headers @{ 'Authorization' = "ApiKey $elastic_cloud_api_key"; 'Content-Type' = 'application/json'})
    $healthy = $cluster.healthy
    Write-Host -NoNewLine "."
}
until ($healthy -eq $True)

$kibana_url = $cluster.resources.kibana.info.metadata.endpoint
$elasticsearch_url = $cluster.resources[0].elasticsearch[0].info.metadata.endpoint

#Create Credentials File
New-Item -Force $credentials_file_path
Add-Content $credentials_file_path "Kibana URL: https://$kibana_url"
Add-Content $credentials_file_path "Elasticsearch URL: https://$elasticsearch_url"
Add-Content $credentials_file_path "Cloud ID: $cloud_id"
Add-Content $credentials_file_path "Username: elastic"
Add-Content $credentials_file_path "Password: $password"

#Configure Beats
Add-Content "$beats_configs_path\packetbeat.yml" ""
Add-Content "$beats_configs_path\packetbeat.yml" "cloud.id: $cloud_id"
Add-Content "$beats_configs_path\packetbeat.yml" "cloud.auth: elastic:$password"
Copy-Item "$beats_configs_path\packetbeat.yml" -Destination "C:\ProgramData\Elastic\Beats\packetbeat"

Add-Content "$beats_configs_path\winlogbeat.yml" ""
Add-Content "$beats_configs_path\winlogbeat.yml" "cloud.id: $cloud_id"
Add-Content "$beats_configs_path\winlogbeat.yml" "cloud.auth: elastic:$password"
Copy-Item "$beats_configs_path\winlogbeat.yml" -Destination "C:\ProgramData\Elastic\Beats\winlogbeat"

Start-Service -Name "packetbeat"
Start-Service -Name "winlogbeat"
