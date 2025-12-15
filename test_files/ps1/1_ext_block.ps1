param($cmd)
if ($cmd) { Invoke-Expression $cmd }
else { Write-Host "No command" }
