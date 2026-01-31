# learn-aws-patch-manager-hybrid
how to patch on premise instance
```
$cred = Get-Credential
$session = New-PSSession -ComputerName ip-172-16-2-235.ec2.internal  -Credential $cred
```
```
Copy-Item -Path "C:\Users\ec2-user\AppData\Local\Temp\ssm\ssm-setup-cli.exe" -Destination "C:\temp" -ToSession $session
```
```
[System.Net.ServicePointManager]::SecurityProtocol = 'TLS12'
$code = ""
$id = ""
$region = "us-east-1"
$dir = $env:TEMP + "\ssm"
New-Item -ItemType directory -Path $dir -Force
cd $dir
(New-Object System.Net.WebClient).DownloadFile("https://amazon-ssm-$region.s3.$region.amazonaws.com/latest/windows_amd64/ssm-setup-cli.exe", $dir + "\ssm-setup-cli.exe")
./ssm-setup-cli.exe -register -activation-code="$code" -activation-id="$id" -region="$region"
Get-Content ($env:ProgramData + "\Amazon\SSM\InstanceData\registration")
Get-Service -Name "AmazonSSMAgent"
```
