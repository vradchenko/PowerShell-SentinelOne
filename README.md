# PowerShell module for SentinelOne

This module provides basic PowerShell cmdlets to work with [SentinelOne](https://www.sentinelone.com/) API functions

## Installation

#### Prerequisites
SentinelOne module for PowerShell requires PowerShell version > 7.0. Check your Powershell version (`$PSVersionTable.PSVersion`) and download > 7.0 from [PowerShell](https://github.com/PowerShell/PowerShell) GitHub page if your Major is < 7.

#### Intallation
Install SentinelOne module from Powershell: `Install-Module -Name SentinelOne`
Alternatively, download PS1 file and import into PowerShell session `. ./SentinelOne.ps1`

## Supported cmdlets
- [Add-S1APIKey](#Add-S1APIKey)
- [Invoke-S1FileFetch](#Invoke-S1FileFetch)
- [Get-S1Agents](#Get-S1Agents)
- [Get-S1APIKey](#Get-S1APIKey)
- [Get-S1DeepVisibility](#Get-S1DeepVisibility)
- [Get-S1SitePolicy](#Get-S1SitePolicy)
- [Remove-S1APIKey](#Remove-S1APIKey)

### Add-S1APIKey
Prerequisites for all other cmdlets to function is to add at least one API token. Key(s) will be stored by default in a user's profile folder (`$env:APPDATA`) in SentinelOneAPI.key file. Before saving API token is encrypted using .NET [System.Security.Cryptography.ProtectedData](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata?view=dotnet-plat-ext-5.0) class using [CurrentUser](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.dataprotectionscope?view=dotnet-plat-ext-5.0)  data protection scope which means that only threads running under the current user context can unprotect the data. API token is never written to a disk in an unprotected format.
#### Parameters
|Parameter|Required|Description|
|--|--|--|
|APIKey|Yes|Secret API key (token) generated with SentinelOne console, a string of 80 chars|
|Endpoint|Yes|SentinelOne console URL, e.g. https://contoso.sentinelone.net|
|Name|Yes|Shortcut to the API key, will be referenced in all other cmdlets, e.g MyKey1|
|Description|No|Any text you'd like to save along with the key, if not provided a current date will be used|
|Path|No|A full path to the encrypted file where a key will be saved. If not provided, a default AppData folder and SentinelOneAPI.key filename will be used|
|ValidateKeyBeforeAdding|No|Switch to validate added API key before saving. Validation happens by executing /web/api/v2.1/users/api-token-details. Default is not to validate|
#### Examples
`Add-S1APIKey -APIKey FeA1KIEfKZE3nYog4dafQfcMg7kTqwktKRrRjKUt99U4rkLz1KZrW7dOLFjsLUgOprzT2bsCc41qbRPv -Name MyKey1 -Endpoint https://contoso.sentinelone.net`
#### Output
A console message indicatingg whenever a key was added succesfully or not.
#### Final notes
You can add as many keys as you want (e.g. keys with different scope or keys from different consoles.
You cannot modify existing keys or add keys with the same name. If any changes are necessary to the existing key you need to delete it with [`Remove-S1APIKey`](#Remove-S1APIKey) first.


### Invoke-S1FileFetch

### Get-S1Agents

### Get-S1APIKey
Lists and gets details of all currently saved API keys
#### Parameters
|Parameter|Required|Description|
|--|--|--|
|Name|No|API key name to get details for, e.g. MyKey1. If not provided all all keys will be displayed (equals to `-Name *`)|
|Path|No|Full path to the encrypted file from where a key will be read. If not provided, a default SentinelOneAPI.key file from AppData folder will be used|
|ValidateKey|No|Switch to validate saved API key. Validation happens by executing /web/api/v2.1/users/api-token-details. Default is not to validate|
|UnmaskKey|No|Switch to show full API key on the screen. If not provided showed key will be masked|
#### Examples
`Get-S1APIKey -Name MyKey1`

`Get-S1APIKey -Name *`

`Get-S1APIKey`
#### Output
An object showing details of the saved key(s).




### Get-S1DeepVisibility

### Get-S1SitePolicy

### Remove-S1APIKey
