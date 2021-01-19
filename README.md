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
Fetches files from an agent. This cmdlet accepts pipe from [Get-S1Agents](#Get-S1Agents) and will fetch same file(S) from all agents returned by Get-S1Agents.
#### Parameters
|Parameter|Required|Description|
|--|--|--|
|APITokenName|Yes|Name of the API token(s) to perform API request|
|Path|No|A full path to the encrypted file from where a token will be read. If not provided, a default AppData folder and SentinelOneAPI.token filename will be used|
|RetryIntervalSec|No|Specifies the interval between retries for the connection when a failure code between 400 and 599, inclusive or 304 is received; default is 5|
|MaximumRetryCount|No|Specifies how many times PowerShell retries a connection when a failure code between 400 and 599, inclusive or 304 is received; default is 2|
|AgentID|Yes|Agent ID to fetch file from|
|File|Yes|Comma-separated files to fetch from the agent. Example: "C:\Windows\notepad.exe", "C:\Users\Public\Documents\flag.txt"|
|Password|No|SentinelOne will encrypt ZIP file with this password. If not provided default password is "Password123"|
|SaveEmptyFetch|No|If requested file(s) are not available on the agent, SentinelOne returns empty ZIP archive and it will not be saved on a disk. Use this switch to force file saving even when it is empty|
|DownloadTimeoutSec|No|File fetch requires agent to be online with the console. This parameter speficies for how many seconds to wait for the fetch upload. Default value is 300 (5 min) and it should be enough to fetch a file from an online agent. Cmdlet stops waiting for file fetch upload once this timer expires (however this does not cancel the fetch request and eventually fetch file will be uploaded to the console when agent gets online). Increase this parameter on slow networks or when fetching files from a big number of agents (using pipe from Get-S1Agents)|
#### Examples
`Invoke-S1FileFetch -APITokenName MyKey1 -AgentID 987623279592853912 -File "C:\windows\UpdateLog.txt", "C:\Program Files\Microsoft\config.xml"`

`Get-S1Agents -APITokenName MyKey1 -ResultSize All ComputerNameContains DESKTOP | Invoke-S1FileFetch -File "C:\windows\UpdateLog.txt", "C:\Program Files\Microsoft\config.xml" -SaveEmptyFetch`

`Get-S1Agents -APITokenName MyKey1 -ResultSize 10 -OSTypes linux | Invoke-S1FileFetch -File "/etc/passwd"` - Gets /etc/passwd file from up to 10 Linux agents

#### Output
Console messages showing fetching progress. Once fetching is finished or expired, an object with a fetch summary is returned (filenames, agent names, status). Fetched files are always saved in the current PoweShell script folder.

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
|IsPendingUninstall|Include agents with pending uninstall requests, $true or $false|
|NumberOfActiveThreatsEqualTo|Include Agents with this number of active threats|
|NumberOfActiveThreatsGreaterThan|Include Agents with at least this number of active threats|
|ScanStatus|Scan status, one from 4 : finished, aborted, started, none|
|MachineTypes|Comma-separated machine types from a set of 5: "kubernetes node", desktop, laptop, server, unknown|
|NetworkStatuses|Comma-separated agents network statutes from a set of 4: connected, connecting, disconnected, disconnecting|
|UserActionsNeeded|Include agents with pending user actions, press 'Tab' to list possible values. Example: reboot_needed, upgrade_needed|
|AgentDomains|Comma-separated agent domain names. Example: contoso.org,lab.dev, workgroup|
#### Examples
`Get-S1Agents -APITokenName MyKey1` returns first 1000 agents from the console

`Get-S1Agents -APITokenName MyKey1 -ResultSize All ComputerNameContains DESKTOP`

`Get-S1Agents -APITokenName MyKey1 -ResultSize 500 -ScanStatus finished -IsInfected $true -OSTypes windows, linux`

`Get-S1Agents -APITokenName MyKey1 -ResultSize All -MachineTypes server -AgentDomains contoso.org`

#### Output
Array of objects representing agents that match the filter.
#### Final notes
There are more agent filters available from the SentinelOne API, however they are not so common so I decided not to implement them. Make an issue if you need other filters!

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
Submits Deep Visibility query and fetches results.
#### Parameters
|Parameter|Required|Description|
|--|--|--|
|APITokenName|Yes|Name of the API token(s) to perform API request|
|Path|No|A full path to the encrypted file from where a token will be read. If not provided, a default AppData folder and SentinelOneAPI.token filename will be used|
|RetryIntervalSec|No|Specifies the interval between retries for the connection when a failure code between 400 and 599, inclusive or 304 is received; default is 5|
|MaximumRetryCount|No|Specifies how many times PowerShell retries a connection when a failure code between 400 and 599, inclusive or 304 is received; default is 2|
|ResultSize|No|Number of events to retrieve, default is 1000, maximum is 20000|
|FetchSize|No|Number of events to retrieve per API call, default is 500, maximum is 1000. Higher number can get results quicker, however timeouts from the API are possible|
|Earliest|Yes|Specifies date of the earliest event to retrieve. Time can be relative or fixed. Relative modifiers are "d" - days, "h" - hours, "m" - minutes, e.g. "-3d" - 3 days ago, "-12h" - 12 hours ago. Fixed time can be specified in flexible formats like "2021-01-10 13:18:21.500", "1/19/2021 3:59:13.000 PM". Keep in mind this is your local time and it will be converted to UTC before submitting the query. To explicilty specify UTC time you need to add "Z" at the end e.g. "2021-01-10 13:18:21.500 Z".
|Latest|No|Specifies data of the latest event to retrieve. If not provided then current time is used. Same as with Earliest time, Latest can be relative or fixed, for more details about the format see Earliest description. Latest should be greater or equal to Earliest.|
|Query|Yes*|Specifies full Deep Visibility query, the same way as it looks in the SentinelOne console e.g. -Query 'SrcProcCmdLine RegExp "schtasks" AND SrcProcParentName != "Manages scheduled tasks"'. Always use ' for string determination since " are used in the query itself. Use Query parameter for advanced, manually created and verified queries.|
|EndpointName, Sha256, Sha1, Md5, FilePath, IP, DstPort, DNS, Name, CmdLine, UserName|Yes*|These are simplified query parameters. Either Query or at least one simplified parameter must be provided. You cannot combine Query with simplified parameters. All simplified parameters will be combined using "AND", and evaluated as "ContainsCIS", e.g. -CmdLine "svchost" -DstPort 445 will be submitted as CmdLine ContainsCIS "svchost" AND DstPort ContainsCIS "445"|
|ObjectType|Yes*|Additional filter to narrow down event to a certain event type, one from "ip", "dns", "process", "cross_process", "indicators", "file", "registry", "scheduled_task", "url", "command_script", "logins".|
|EventType|Yes*|Additional filter to narrow down the search even further, by specifying certain evnts like "File Creation", "Registry Value Modified" or "Task Register". Full list is availalbe with auto completion in the script|
#### Examples
`Get-S1DeepVisibility -APITokenName MyKey1 -Earliest -24h -Query 'SrcProcCmdLine RegExp "schtasks" AND SrcProcParentName != "Manages scheduled tasks"`

`Get-S1DeepVisibility -APITokenName MyKey1 -Earliest -7d -Latest -6d -EndpointName DESKTOP-RC4DWK -ObjectType dns`

`Get-S1DeepVisibility -APITokenName MyKey1 -Earliest "2021-01-10 13:18:21.500" -Latest -180m -EventType "Task Start"`

`Get-S1DeepVisibility -APITokenName MyKey1 -Earliest -90d IP "192.168.0.1" -DstPort 80 -CmdLine chrome`
#### Output
Console messages showing progress of request and an array of objects containing Deep Visibility events.
#### Final notes
Overall cmdlet process is: first query is submitted, then script waits for query to finish and then fetches the results. Sometimes submitted queries cannot be completed (Deep Visibility timeout) - in this case script will throw an error when all http retries are used. Fetching the maximum set (20000 events) can take a while, always save cmdlete results to a variable like $events = Get-S1DeepVisibility ... unless you're expecting only a few results (or no results).

### Get-S1SitePolicy
Get site policy settings from a siteID. This cmdlet accepts pipe from [Get-S1Agents](#Get-S1Agents).
#### Parameters
|Parameter|Required|Description|
|--|--|--|
|APITokenName|Yes|Name of the API token(s) to perform API request|
|Path|No|A full path to the encrypted file from where a token will be read. If not provided, a default AppData folder and SentinelOneAPI.token filename will be used|
|RetryIntervalSec|No|Specifies the interval between retries for the connection when a failure code between 400 and 599, inclusive or 304 is received; default is 5|
|MaximumRetryCount|No|Specifies how many times PowerShell retries a connection when a failure code between 400 and 599, inclusive or 304 is received; default is 2|
|SiteId|Yes|Unique site ID to get policy settings for|
#### Examples
`Get-S1SitePolicy -APITokenName MyKey1 -SiteId 987654321123456789`

`Get-S1Agents -APITokenName MyKey1 -ResultSize 250 ComputerNameContains DESKTOP | Get-S1SitePolicy` This will get policy settings for all sites where all agents from the first cmdlet are located.

`Get-S1Agents -APITokenName MyKey1 -ResultSize All | Get-S1SitePolicy | Select-Object mitigationMode` This will show mitigationMode settings from all policies applies to all agents.
#### Output
Array of objects representing policy settings for a given site ID.
#### Final notes
Piping from Get-S1Agents is the easiest way to use this cmdlet, else you need to provide a numerical siteID.










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
