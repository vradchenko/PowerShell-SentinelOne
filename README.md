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
|Parameter|Required|Description|Example
|--|--|--|--|
|APIKey|Yes|Secret API key (token) generated with SentinelOne console|GrD7dVSMjsSBgVprzA
|Endpoint|Yes|SentinelOne console URL|https://contoso.sentinelone.net
|Name|Yes|Shortcut to the API key, will be referenced in all other cmdlets|MyKey1
|Description|No|Any text you'd like to save along with the key, if not provided a current date will be used|Key provided by XYZ, expiries DD.MM.YYYY
|Path|No|Path to the encrypted file where a key will be saved. If not provided, a default `$env:APPDATA`\SentinelOneAPI.key will be used|C:\Folder\mykeys.api
|ValidateKeyBeforeAdding|No|Switch to validate added API key before saving. Validation happens by executing /web/api/v2.1/users/api-token-details. Default is not to validate
#### Examples
`Add-S1APIKey -APIKey GrD7dVSMjsSBgVprzA -Name MyKey1 -Endpoint https://contoso.sentinelone.net`
#### Output
A console message indication whenever a key was added succesfully or not.
#### Final notes
You can add as many keys as you want (e.g. keys with different scope or keys from different consoles.
You cannot modify existing keys or add keys with the same name. If any changes are necessary to the existing key you need to delete it with [Remove-S1APIKey](#Remove-S1APIKey) first.


### Invoke-S1FileFetch

### Get-S1Agents

### Get-S1APIKey

### Get-S1DeepVisibility

### Get-S1SitePolicy

### Remove-S1APIKey
