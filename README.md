# Kerb2SPNegoToken
A powershell script to obtain a SPNEGO token. This can be used with Entra Seamless SSO.

## Usage
```
Import-Module .\Kerb2SPNegoToken.ps1
$token = Get-SPNEGOToken
...
// Use token for in authorization header with Negotiate
```