# PowerShell module for SentinelOne

This module provides basic PowerShell cmdlets to work with [SentinelOne](https://www.sentinelone.com/) API functions

## Installation

### Prerequisites
SentinelOne module for PowerShell requires PowerShell version > 7.0. Check your Powershell version (`$PSVersionTable.PSVersion`) and download > 7.0 from [PowerShell](https://github.com/PowerShell/PowerShell) GitHub page if your Major is < 7.

### Installation
Install SentinelOne module from Powershell: `Install-Module -Name SentinelOne`
Alternatively, download 'Invoke-WebRequest https://github.com/' file and import into PowerShell session `. ./SentinelOne.ps1`

## Supported cmdlets
- [Add-S1APIToken](#Add-S1APIToken)
- [Invoke-S1FileFetch](#Invoke-S1FileFetch)
- [Get-S1Agents](#Get-S1Agents)
- [Get-S1APIToken](#Get-S1APIToken)
- [Get-S1DeepVisibility](#Get-S1DeepVisibility)
- [Get-S1SitePolicy](#Get-S1SitePolicy)
- [Remove-S1APIToken](#Remove-S1APIToken)

### Add-S1APIToken
Prerequisites for all other cmdlets to function is to add at least one API token. Key(s) will be stored by default in a user's profile folder (`$env:APPDATA`) in SentinelOneAPI.key file. Before saving API token is encrypted using .NET [System.Security.Cryptography.ProtectedData](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata?view=dotnet-plat-ext-5.0) class using [CurrentUser](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.dataprotectionscope?view=dotnet-plat-ext-5.0)  data protection scope which means that only threads running under the current user context can unprotect the data. API token is never written to a disk in an unprotected format.
#### Parameters
|Parameter|Required|Description|
|--|--|--|
|APIToken|Yes|Secret API token generated with SentinelOne console, a string of 80 chars|
|Endpoint|Yes|SentinelOne console URL, e.g. https://contoso.sentinelone.net|
|APITokenName|Yes|Shortcut to the API token, will be referenced in all other cmdlets, e.g MyKey1|
|Description|No|Any text you'd like to save along with the token, if not provided a current date will be used|
|Path|No|A full path to the encrypted file where a token will be saved. If not provided, a default AppData folder and SentinelOneAPI.token filename will be used|
|DoNotValidateToken|No|Switch to disable token validation before saving. If not provided, validation happens by executing /web/api/v2.1/users/api-token-details|
#### Examples
`Add-S1APIToken -APIToken FeA1KIEfKZE3nYog4dafQfcMg7kTqwktKRrRjKUt99U4rkLz1KZrW7dOLFjsLUgOprzT2bsCc41qbRPv -APITokenName MyKey1 -Endpoint https://contoso.sentinelone.net`
#### Output
A console message indicating whenever a token was added succesfully or not.
#### Final notes
You can add as many tokens as you want (e.g. tokens with different scope or tokens from different consoles).
You cannot modify existing tokens or add tokens with the same name. If any changes are necessary to the existing tokens you need to delete it with [`Remove-S1APIKey`](#Remove-S1APIToken) first.

### Invoke-S1FileFetch

### Get-S1Agents
Get the agents and their data, that match the filter. This command also returns the Agent ID, which is a required attribute for other cmdlets (e.g. for [`Invoke-S1FileFetch`](#Invoke-S1FileFetch).
#### Parameters
|Parameter|Required|Description|
|--|--|--|
|APITokenName|Yes|Name of the API token(s) to perform API request|
|Path|No|A full path to the encrypted file from where a token will be read. If not provided, a default AppData folder and SentinelOneAPI.token filename will be used|
|RetryIntervalSec|No|Specifies the interval between retries for the connection when a failure code between 400 and 599, inclusive or 304 is received; default is 5|
|MaximumRetryCount|No|Specifies how many times PowerShell retries a connection when a failure code between 400 and 599, inclusive or 304 is received; default is 2|
|ResultSize|No|Number of agents to return, default is 1000, use -ResultSize All to get all agents|
#### Filter parameters
All filter parameters are optional, if nothing is provided Get-S1Agents gets all registered agents.
|Filter parameter|Description|
|--|--|
|ComputerNameContains|Comma-separated hostnames, e.g. DESKTOP, HOST|
|OSTypes|Comma-separated OS types from a set of 4: windows, linux, macos, windows_legacy, e.g. windows, macos|
|AgentVersions|Agent versions to include, e.g. 2.0.0.0,2.1.5.144|
|IsActive|Include only active Agents, $true or $false|
|IsInfected|Include only agents with at least one active threat, $true of $false|
|IsUpToDate|Include only agents with updated software, $true of $false|
|NumberOfActiveThreatsEqualTo|Include Agents with this number of active threats|
|NumberOfActiveThreatsGreaterThan|Include Agents with at least this number of active threats|
|ScanStatus|Scan status, one from 4 : finished, aborted, started, none|
|MachineTypes|Comma-separated machine types from a set of 5: kubernetes node, desktop, laptop, server, unknown|
#### Examples
`Get-S1Agents -APITokenName MyKey1` returns first 1000 agents from the console
`Get-S1Agents -APITokenName MyKey1 -ResultSize All ComputerNameContains DESKTOP` returns all agents from the console where computer name contains "DESKTOP"
#### Output
Array of objects representing agents that match the filter.





### Get-S1APIToken
Lists and gets details of all currently saved API tokens
#### Parameters
|Parameter|Required|Description|
|--|--|--|
|APITokenName|No|API token name to get details for, e.g. MyKey1. If not provided all tokens will be displayed (equals to `-APITokenName *`)|
|Path|No|A full path to the encrypted file from where a token will be read. If not provided, a default AppData folder and SentinelOneAPI.token filename will be used|
|ValidateAPIToken|No|Switch to validate saved API key. Validation happens by executing /web/api/v2.1/users/api-token-details. Default is not to validate|
|UnmaskAPIToken|No|Switch to show full API key on the screen. If not provided showed key will be masked|
#### Examples
`Get-S1APIKey -APITokenName MyKey1 -ValidateAPIToken`
`Get-S1APIKey -APITokenName *`
`Get-S1APIKey -UnmaskAPIToken`
#### Output
An object showing details of the saved token(s).


### Get-S1DeepVisibility

### Get-S1SitePolicy

### Remove-S1APIToken
Removes currently saved API tokens
#### Parameters
|Parameter|Required|Description|
|--|--|--|
|APITokenName|Yes|API token name to remove, e.g. MyKey1)|
|Path|No|A full path to the encrypted file from where a token will be removed. If not provided, a default AppData folder and SentinelOneAPI.token filename will be used|
#### Examples
`Remove-S1APIKey -APITokenName MyKey1`
#### Output
No output when removed successfully.
