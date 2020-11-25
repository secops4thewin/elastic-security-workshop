
$install_dir = "C:\Elastic"
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
# Upload each rule to Elastic
$ruleList = @("$install_dir\AdversaryEmulation001.ndjson", "$install_dir\AdversaryEmulation002.ndjson", "$install_dir\AdversaryEmulation003.ndjson", "$install_dir\AdversaryEmulation004.ndjson")
foreach ($rule in $ruleList)
{
Write-Output "Adding Rule $rule"
$jsonParse = get-content -raw $rule | convertfrom-json
$newObj = $jsonParse | select-object -property * -excludeproperty created_at, created_by, updated_at, immutable, meta, output_index
$bodyRequest = $jsonParse | ConvertTo-Json -Depth 32

Invoke-RestMethod "https://$kibana_url/api/detection_engine/rules" -Method 'POST' -Headers $headers -body $bodyRequest
}