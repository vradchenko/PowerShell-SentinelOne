#This module requires Powershell 7 or higher
#Requires -Version 7.0

class SentinelOne
{
	[Hashtable]$APITokens = @{}
	[String]$Path
	[Datetime]$GetDate
	[Int]$RetryIntervalSec = 2
	[Int]$MaximumRetryCount = 2

	#API endpoints
	[Hashtable]$APIEndpoints = @{
		ApiTokenDetails = @{Method = "POST"; URI = "web/api/v2.1/users/api-token-details"};
		GetAgents = @{Method = "GET"; URI = "web/api/v2.1/agents"};
		CreateQueryAndGetQueryid = @{Method = "POST"; URI = "web/api/v2.1/dv/init-query"};
		GetQueryStatus = @{Method = "GET"; URI = "web/api/v2.1/dv/query-status?queryId="};
		GetEvents = @{Method = "GET"; URI = "web/api/v2.1/dv/events?sortBy=createdAt&queryId="};
		GetActivities = @{Method = "GET"; URI = "web/api/v2.1/activities?sortBy=createdAt&sortOrder=desc&limit=1000&activityTypes="};
		FetchFiles = @{Method = "POST"; URI = "web/api/v2.1/agents/{agent_id}/actions/fetch-files"};
		SitePolicy = @{Method = "GET"; URI = "web/api/v2.1/sites/{site_id}/policy"}}

	SentinelOne($Path)
	{
		$this.Path = $Path
		$this.ReadAPITokens()
		$this.GetDate = Get-Date
	}

	[PSObject] MakeHTTPRequest($APITokenName, $RequestName, $Parameters)
	{
		$Headers = @{Authorization = "APIToken $($this.APITokens.$APITokenName.APIToken)"}
		$URI = $this.APITokens.$APITokenName.Endpoint + $this.APIEndpoints.$RequestName.URI
		switch ($RequestName)
			{
				"GetAgents" { $URI += $Parameters[0]; break}
				"GetQueryStatus" { $URI += $Parameters[0]; break}
				"GetEvents" { $URI += $Parameters[0] + "&cursor=" + $Parameters[1] + "&limit=" + $Parameters[2]; break}
				"FetchFiles" { $URI = $URI.Replace("{agent_id}", $Parameters[1]); break}
				"GetActivities" { $URI += $Parameters[0]; break}
				"SitePolicy" { $URI = $URI.Replace("{site_id}", $Parameters[0]); break}
				Default {}
			}

		if ($this.APIEndpoints.$RequestName.Method -eq "GET")
		{
			return Invoke-RestMethod -Uri $URI -Method GET -Headers $Headers -RetryIntervalSec $this.RetryIntervalSec -MaximumRetryCount $this.MaximumRetryCount -ContentType "application/json"
		}
		else
		{
			#$Parameters[0] should be a POST body, JSON formatted
			return Invoke-RestMethod -Uri $URI -Method POST -Headers $Headers -RetryIntervalSec $this.RetryIntervalSec -MaximumRetryCount $this.MaximumRetryCount -ContentType "application/json" -Body $Parameters[0]
		}
	}

	[Bool] ValidateAPIToken($APITokenName, $ThrowIfInvalid)
	{
		$Body = ConvertTo-Json -Compress -InputObject $(@{data = @{apiToken = $this.APITokens.$APITokenName.APIToken}})
		try
		{
			$http = $this.MakeHTTPRequest($APITokenName, "ApiTokenDetails", @($Body))
		}
		catch
		{
			if ($ThrowIfInvalid)
			{
				throw "Failed to verify API token. Please check Endpoint and APIToken parameters"
			}
			else
			{
				return $false
			}
		}
		$this.APITokens.$APITokenName.ExpiresAt = $http.data.expiresAt
		return $true
	}

	[Void] SaveHTTPRetryParameters($RetryIntervalSec, $MaximumRetryCount)
	{
		$this.RetryIntervalSec = $RetryIntervalSec
		$this.MaximumRetryCount = $MaximumRetryCount
	}

	[Bool] Hidden ReadAPITokens()
	{
		try
		{
			$read = [System.IO.File]::ReadAllBytes($this.Path)
			$read = [System.Security.Cryptography.ProtectedData]::Unprotect($read, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
			$read = [System.Text.Encoding]::Unicode.GetString($read)
			$read = ConvertFrom-Json -InputObject $read -AsHashtable
		}
		catch
		{
			return $false
		}
		$this.APITokens = $read
		return $true
	}

	[Bool] Hidden WriteAPITokens()
	{
		try
		{
			$write = ConvertTo-Json -InputObject $this.APITokens -Compress
			$write = [System.Text.Encoding]::Unicode.GetBytes($write)
			$write = [System.Security.Cryptography.ProtectedData]::Protect($write, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
			[System.IO.File]::WriteAllBytes($this.Path, $write)
		}
		catch
		{
			throw "Cannot encrypt and/or save API tokens to $($this.Path)"
		}
		return $true
	}

	[Bool] AddAPIToken($APIToken, $Endpoint, $APITokenName, $Description, $DoNotValidateToken)
	{
		#Ensuring API token name is not *
		if ($APITokenName -eq "*")
		{
			throw "Name cannot be equal to *"
		}
		#Ensuring Endpoint URL contains / at the end
		if ($Endpoint -notmatch "/$")
		{
			$Endpoint += "/"
		}
		#Ensuring endpoing looks like a SentineOne URL
		if ($Endpoint -notmatch "^https://[\w\S]+\.sentinelone.net/$")
		{
			throw "Wrong Endpoint provided. Proper format is e.g. https://contoso.sentinelone.net/"
		}

		if ($this.APITokens.ContainsKey($APITokenName))
		{
			throw "Saved API tokens already contain a token with name $APITokenName. Remove existing token with `"Remove-S1APIToken -Name $APITokenName`""
		}
		
		$this.APITokens.Add($APITokenName, @{"APIToken" = $APIToken; "Endpoint" = $Endpoint; "Description" = $Description})

		if ($DoNotValidateToken -eq $false)
		{
			$this.ValidateAPIToken($APITokenName, $true)
		}
	
		$this.WriteAPITokens()
		return $true
	}

	[Void] RemoveAPIToken($APITokenName)
	{
		if ($APITokenName -eq "*")
		{
			throw "API token name cannot be equal to *"
		}
		if (!$this.APITokens.ContainsKey($APITokenName))
		{
			throw "No saved API token with name $APITokenName."
		}
		$this.APITokens.Remove($APITokenName)
		$this.writeAPITokens()
	}

	[String] Hidden PrepareGetFilter($Parameters)
	{
		$filter = ""
	
		foreach ($Key in $Parameters.Keys)
		{
			switch -Exact ($Key)
			{
				"ComputerNameContains" { $filter += "&computerName__contains="+$($Parameters[$Key] -join ","); Break }
				"OSTypes" { $filter += "&osTypes="+$($Parameters[$Key] -join ","); Break }
				"AgentVersions" { $filter += "&agentVersions="+$($Parameters[$Key] -join ","); Break }
				"IsActive" { $filter += "&isActive="+$($Parameters[$Key]); Break }
				"IsInfected" { $filter += "&infected="+$($Parameters[$Key]); Break }
				"IsUpToDate" { $filter += "&isUpToDate="+$($Parameters[$Key]); Break }
				"NumberOfActiveThreatsEqualTo" { $filter += "&activeThreats="+$($Parameters[$Key]); Break }
				"NumberOfActiveThreatsGreaterThan" { $filter += "&activeThreats__gt="+$($Parameters[$Key]); Break }
				"ScanStatus" { $filter += "&scanStatus="+$($Parameters[$Key]); Break }
				"MachineTypes" { $filter += "&machineTypes="+$($Parameters[$Key] -join ","); Break }
				"UserActionsNeeded" { $filter += "&userActionsNeeded="+$($Parameters[$Key] -join ","); Break }
				"NetworkStatuses" { $filter += "&networkStatuses="+$($Parameters[$Key] -join ","); Break }
				"AgentDomains" { $filter += "&domains="+$($Parameters[$Key] -join ","); Break }
				"IsPendingUninstall" { $filter += "&isPendingUninstall="+$($Parameters[$Key]); Break }
				"IsDecommissioned" { $filter += "&isDecommissioned="+$($Parameters[$Key]); Break }
				Default {}
			}
		}
		return $filter
	}
	
	[PSCustomObject] GetAgents($APITokenName, $ResultSize, $Parameters)
	{
		$Return = @()
		$GetAll = $false
		if ($ResultSize -eq "All")
		{
			$ResultSize = 1000
			$GetAll = $true
		}
		$Filter = "?$($this.PrepareGetFilter($Parameters))&limit=$ResultSize"
		$FilterCursor = $Filter
		$TotalAgents = 0
		Do
		{
			$Http = $this.MakeHTTPRequest($APITokenName, "GetAgents", @($FilterCursor))
			$Http.data | Add-Member -Value $APITokenName -Name "APITokenName" -MemberType NoteProperty
			$Return += $Http.data
			$FilterCursor = $Filter + "&cursor=$($Http.pagination.nextCursor)"
			if ($Http.pagination.totalItems -gt 0)
			{
				$TotalAgents = $Http.pagination.totalItems
			}
			if ($TotalAgents -gt 1)
			{
				Write-Host "Completed $($Return.Count) agents from $TotalAgents using API token $APITokenName..."
			}
		} While ($GetAll -and $null -ne $Http.pagination.nextCursor)
		return $Return
	}

	[Void] CheckAPITokenName($APITokenNames)
	{
		foreach ($APITokenName in $APITokenNames)
		{
			if(!$this.APITokens.ContainsKey($APITokenName))
			{
				throw "No saved API token with name $APITokenName"
			}
		}
	}
	
	[Datetime] parseRange($range)
	{
		#Relative range
		if ($range -match "^-\d+[hmd]$")
		{
			$number = [int]((Select-String -InputObject $range -Pattern "\d+").Matches.Value)
			switch ((Select-String -InputObject $range -Pattern "[mhd]").Matches.Value)
			{
				"m" { return $this.getDate.AddMinutes($number*-1) }
				"h" { return $this.getDate.AddMinutes($number*60*-1) }
				"d" { return $this.getDate.AddMinutes($number*60*24*-1) }
				Default {throw "Error parsing range"}
			}
		}
		else
		{
			try
			{
				$date = Get-Date -Date $range
			}
			catch
			{
				throw "Cannot parse date"
			}
			return $date
		}
		return $this.getDate
	}

	[String] submitDVQuery($APITokenName, $Query)
	{
		$Http = $this.MakeHTTPRequest($APITokenName, "CreateQueryAndGetQueryid", @($Query))
		$QueryId = $Http.data.queryId
		if ($QueryId -match "q[a-f0-9]{32}")
		{
			return $QueryId
		}
		else
		{
			throw "Unexpected query ID format"
		}
	}

	[Hashtable] getQueryStatus($APITokenName, $QueryID)
	{
		$Http = $this.MakeHTTPRequest($APITokenName, "GetQueryStatus", @($QueryID))
		return @{progressStatus = $Http.data.progressStatus; responseState = $Http.data.responseState}
	}

	[Bool] RequestFileFetch($APITokenName, $AgentID, $File, $Password)
	{
		$PostBody = @{data = @{files = $File; password = $Password}}
		$PostBody = ConvertTo-Json -Compress -InputObject $PostBody
		$Http = $this.MakeHTTPRequest($APITokenName, "FetchFiles", @($PostBody, $AgentID))		
		if ($Http.data.success -eq $true)
		{
			return $true
		}
		return $false
	}

	[PSCustomObject] RequestFileFetchActivityPage($APITokenName, $Code)
	{
		$Http = $this.MakeHTTPRequest($APITokenName, "GetActivities", @($Code))
		$Http.data | Add-Member -Value $APITokenName -Name "APITokenName" -MemberType NoteProperty
		return $Http.data
	}

	[Bool] RequestFileFetchDownload($APITokenName, $DownloadUrl, $Filename, $SaveEmptyFetch)
	{
		[System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression")
		$URI = $this.APITokens[$APITokenName].Endpoint + "web/api/v2.1" + $DownloadUrl
		$OutFile = $(Get-Location).Path + "\" + $Filename + ".zip"
		$ZipFileFetch = Invoke-WebRequest -Uri $URI -Method GET -Headers @{Authorization = "APIToken "+$this.APITokens[$APITokenName].APIToken} -RetryIntervalSec $this.RetryIntervalSec -MaximumRetryCount $this.MaximumRetryCount
		$ZipStream = New-Object System.IO.Memorystream
		$ZipStream.Write($ZipFileFetch.Content,0,$ZipFileFetch.Content.Length)
		$ZipFile = [System.IO.Compression.ZipArchive]::new($ZipStream)
		if ($SaveEmptyFetch -or $ZipFile.Entries.Count -gt 1)
		{
			$ZipFileFetch.Content | Set-Content -Path $OutFile -AsByteStream
			Write-Host "File saved to $OutFile" -ForegroundColor Green
			return $true
		}
		else
		{
			Write-Host "$Filename.zip was fetched, but appear to be empty. Not saving." -ForegroundColor Red
			return $false
		}

	}

	[PSCustomObject] GetS1SitePolicy($APITokenName, $SiteId, $SiteName)
	{
		$Http = $this.MakeHTTPRequest($APITokenName, "SitePolicy", @($SiteId))
		$Http.data | Add-Member -Value $APITokenName -Name "APITokenName" -MemberType NoteProperty
		$Http.data | Add-Member -Value $SiteName -Name "siteName" -MemberType NoteProperty
		$Http.data | Add-Member -Value $SiteId -Name "siteId" -MemberType NoteProperty
		return $Http.data
	}

	[PSCustomObject] GetQueryData($APITokenName, $QueryID, $FetchSize)
	{
		$Return = @()
		$NextCursor = ""
		$TotalItems = 0

		Do
		{
			$Http = $this.MakeHTTPRequest($APITokenName, "GetEvents", @($QueryID, $NextCursor, $FetchSize))
			$Http.data | Add-Member -Value $APITokenName -Name "APITokenName" -MemberType NoteProperty
			$Return += $Http.data | Select-Object -ExcludeProperty attributes
			$NextCursor = $Http.pagination.nextCursor
			if ($Http.pagination.totalItems -gt 0 -and $TotalItems -eq 0)
			{
				$TotalItems = $Http.pagination.totalItems
			}
			if ($TotalItems -gt 0)
			{
				Write-Host "Fetched $($Return.Count) Deep Visibility events from total $TotalItems using API token $APITokenName..."
			}
		} While ($null -ne $Http.pagination.nextCursor)
		return $Return
	}
}

function Add-S1APIToken
{
	[CmdletBinding()]
	Param(

		[Parameter(Mandatory, HelpMessage="Enter SentinelOne API token name")]
		[String] $APITokenName,

		[Parameter(Mandatory, HelpMessage="Enter SentinelOne API token")]
		[ValidateLength(80,80)]
		[String] $APIToken,
			
		[Parameter(Mandatory, HelpMessage="Enter SentinelOne API token endpoint URL (e.g. https://contoso.sentinelone.net/)")]
		[String] $Endpoint,

		[Parameter(HelpMessage="You can provide and save comments to the API token")]
		[String] $Description = $("API token added $(Get-Date)"),

		[Parameter(HelpMessage="Full path to encrypted file to save API token")]
		[ValidateNotNullOrEmpty()]
		[String] $Path = $(Join-Path $env:APPDATA "SentinelOneAPI.token"),
		
		[Switch] $DoNotValidateToken
		)
		
	$API = [SentinelOne]::new($Path)

	if ($API.AddAPIToken($APIToken, $Endpoint, $APITokenName, $Description, $DoNotValidateToken) -eq $true)
	{
		Write-Host "API token `"$APITokenName`" added successfully." -ForegroundColor Green
	}
	else
	{
		Write-Host "Failed to add API token `"$APITokenName`"." -ForegroundColor Red
	}
}

function Get-S1APIToken
{
	[CmdletBinding()]
	Param(
		[Parameter(HelpMessage="Enter SentinelOne API token name")]
		[ValidateNotNullOrEmpty()]
		[String] $APITokenName = "*",

		[Parameter(HelpMessage="Full path to encrypted file to load API token")]
		[ValidateNotNullOrEmpty()]
		[String] $Path = $(Join-Path $env:APPDATA "SentinelOneAPI.token"),
		
		[Switch] $ValidateAPIToken,
		[Switch] $UnmaskAPIToken
		)

	$API = [SentinelOne]::new($Path)
	$Tokens = @()

	foreach ($Name in $API.APITokens.Keys)
	{
		$APITokenHashTable = [Ordered]@{APITokenName = $Name; Endpoint = $API.APITokens.$Name.Endpoint; Description = $API.APITokens.$Name.Description; APIToken = ($API.APITokens.$Name.APIToken.Substring(0,5)+"*"*75)}
		if ($UnmaskAPIToken)
		{
			$APITokenHashTable.APIToken = $API.APITokens.$Name.APIToken
		}
		if ($ValidateAPIToken)
		{
			$APITokenHashTable.IsValid = $API.ValidateAPIToken($Name, $false)
			$APITokenHashTable.ExpiresAt = $API.APITokens.$Name.ExpiresAt
		}
		$Tokens += [PSCustomObject]$APITokenHashTable
	}
	if ($APITokenName -eq "*")
	{
		return $Tokens
	}
	else
	{
		return ($Tokens | Where-Object APITokenName -eq $APITokenName)
	}
	
}

function Remove-S1APIToken
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory, HelpMessage="Enter SentinelOne API token name")]
		[String] $APITokenName,

		[Parameter(HelpMessage="Full path to encrypted file to load API token")]
		[ValidateNotNullOrEmpty()]
		[String] $Path = $(Join-Path $env:APPDATA "SentinelOneAPI.token")
	)

	$API = [SentinelOne]::new($Path)
	$API.RemoveAPIToken($APITokenName)
}

function Get-S1Agents
{
	[CmdletBinding(PositionalBinding = $false)]
	Param(
		[Parameter(Mandatory, HelpMessage="Enter SentinelOne API token name")]
		[String[]] $APITokenName,

		[Parameter(HelpMessage="Full path to encrypted file to load API token")]
		[ValidateNotNullOrEmpty()]
		[String] $Path = $(Join-Path $env:APPDATA "SentinelOneAPI.token"),

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({$_ -eq "All" -or ([Int]::Parse($_) -ge 1 -and [int]::Parse($_) -le 1000)})]
		[String] $ResultSize = "1000",

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Int] $RetryIntervalSec = 5,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Int] $MaximumRetryCount = 2,
		
		#Get-S1Agents filters
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[String[]] $ComputerNameContains,

		[Parameter()]
		[ValidateSet("linux","macos","windows", "windows_legacy")]
		[String[]] $OSTypes,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[String[]] $AgentVersions,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Bool] $IsActive,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Bool] $IsInfected,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Bool] $IsUpToDate,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Int] $NumberOfActiveThreatsEqualTo,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Int] $NumberOfActiveThreatsGreaterThan,

		[Parameter()]
		[ValidateSet("finished","aborted","started", "none")]
		[String] $ScanStatus,

		[Parameter()]
		[ValidateSet("kubernetes node","desktop","laptop", "server", "unknown")]
		[String[]] $MachineTypes,

		[Parameter()]
		[ValidateSet("agent_suppressed_category", "incompatible_os", "incompatible_os_category", "missing_permissions_category", "none", "reboot_category", "reboot_needed",
		"unprotected", "unprotected_category", "upgrade_needed", "user_action_needed", "user_action_needed_fda", "user_action_needed_network", "user_action_needed_rs_fda")]
		[String[]] $UserActionsNeeded,

		[Parameter()]
		[ValidateSet("connected", "connecting", "disconnected", "disconnecting")]
		[String[]] $NetworkStatuses,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[String[]] $AgentDomains,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Bool] $IsPendingUninstall,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Bool] $IsDecommissioned
	)
	
	$API = [SentinelOne]::new($Path)
	$API.CheckAPITokenName($APITokenName)
	$API.SaveHTTPRetryParameters($RetryIntervalSec, $MaximumRetryCount)
	$Return = @()
	foreach ($Name in $APITokenName)
	{
		$Return += $API.GetAgents($Name, $ResultSize, $PSBoundParameters)
	}
	return $Return
}

function Get-S1DeepVisibility
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory, HelpMessage="Enter SentinelOne API token name")]
		[String[]] $APITokenName,

		[Parameter(HelpMessage="Full path to encrypted file to load API token")]
		[ValidateNotNullOrEmpty()]
		[String] $Path = $(Join-Path $env:APPDATA "SentinelOneAPI.token"),

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({[Int]::Parse($_) -ge 1 -and [int]::Parse($_) -le 20000})]
		[String] $ResultSize = "1000",

		[ValidateNotNullOrEmpty()]
		[Int] $FetchSize = 500,

		[ValidateNotNullOrEmpty()]
		[Int] $RetryIntervalSec = 5,

		[ValidateNotNullOrEmpty()]
		[Int] $MaximumRetryCount = 36,

		[Parameter(HelpMessage="Enter Deep Visibility search query", ParameterSetName="Advanced")]
		[ValidateNotNullOrEmpty()]
		[String] $Query,
		
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()][String] $EndpointName,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()][String] $Sha256,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()][String] $Sha1,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()][String] $Md5,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()][String] $FilePath,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()][String] $IP,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()][String] $DNS,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()][String] $Name,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()][String] $CmdLine,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()][String] $UserName,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()][String] $DstPort,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()]
		[ArgumentCompleter(
			{
				param ($a,$b,$c,$d,$e)
				$types = @{Types = @("ip", "dns", "process", "cross_process", "indicators", "file", "registry", "scheduled_task", "url", "command_script", "logins")};
				$types.Values | ForEach-Object {$_}
			})]
		[String] $ObjectType,
		[Parameter(ParameterSetName="Simple")][ValidateNotNullOrEmpty()]
		[ArgumentCompleter(
			{
				param ($a,$b,$c,$d,$e)
				$types = @{Types = @("Login", "`"Registry Key Export`"", "Logout", "Unknown", "`"Pre Execution Detection`"", "Command Script", "HEAD", "DELETE", "Registry Key Security Changed", "File Scan", "PUT", "Remote Thread Creation", "OPTIONS", "DNS Unresolved", "Task Register", "Task Delete", "Task Update", "Duplicate Thread Handle", "IP Listen", "Task Start", "CONNECT", "GET", "Registry Value Create", "DNS Resolved", "Registry Key Create", "Process Creation", "Open Remote Process Handle", "Behavioral Indicators", "Duplicate Process Handle", "Task Trigger", "POST", "File Deletion", "Registry Value Modified", "Registry Value Delete", "Registry Key Delete", "Not Reported", "IP Connect", "File Modification", "File Creation", "File Rename")};
				$types.Values | ForEach-Object {$_}
			})]
		[String] $EventType,
		
		[Parameter(Mandatory, HelpMessage="Enter Deep Visibility search range")]
		[String] $Earliest,
		
		[Parameter(HelpMessage="Enter Deep Visibility search range")]
		[ValidateNotNullOrEmpty()]
		[String] $Latest
		)
		
	$API = [SentinelOne]::new($Path)
	$API.CheckAPITokenName($APITokenName)
	$API.SaveHTTPRetryParameters($RetryIntervalSec, $MaximumRetryCount)

	$fromDate = $API.ParseRange($Earliest)
	$fromDate = $(Get-Date -Date $($(Get-Date -Date $fromDate).ToUniversalTime()) -Format O)
	
	if($PSBoundParameters.ContainsKey("Latest"))
	{
		$toDate = $API.parseRange($Latest)
		$toDate = $(Get-Date -Date $($(Get-Date -Date $toDate).ToUniversalTime()) -Format O)
		if ($fromDate -gt $toDate)
		{
			throw "Latest is before Earliest!"
		}
	}
	else
	{
		$toDate = $(Get-Date)
		$toDate = $(Get-Date -Date $($(Get-Date -Date $toDate).ToUniversalTime()) -Format O)
	}

	Write-Host "Search time:" -ForegroundColor Green
	Write-Host "   From: $(Get-Date -Date $($(Get-Date -Date $fromDate).ToUniversalTime()) -Format "dddd, MMMM dd, yyyy HH:mm:ss.fff")"
	Write-Host "   To:   $(Get-Date -Date $($(Get-Date -Date $toDate).ToUniversalTime()) -Format "dddd, MMMM dd, yyyy HH:mm:ss.fff")"
   
	#Building DV query
	$QueryToRun = ""
	foreach ($Key in $PSBoundParameters.Keys)
	{
		switch -Exact ($Key)
		{
			"Query" { $QueryToRun = " AND "+$query; Break }
			"Sha256" {$QueryToRun += " AND Sha256 ContainsCIS `""+$Sha256+"`""; Break }
			"Sha1" {$QueryToRun += " AND Sha1 ContainsCIS `""+$Sha1+"`""; Break }
			"Md5" {$QueryToRun += " AND Md5 ContainsCIS `""+$Md5+"`""; Break }
			"FilePath" {$QueryToRun += " AND FilePath ContainsCIS `""+$FilePath+"`""; Break }
			"IP" {$QueryToRun += " AND IP ContainsCIS `""+$IP+"`""; Break }
			"DNS" {$QueryToRun += " AND DNS ContainsCIS `""+$DNS+"`""; Break }
			"Name" {$QueryToRun += " AND Name ContainsCIS `""+$Name+"`""; Break }
			"CmdLine" {$QueryToRun += " AND CmdLine ContainsCIS `""+$CmdLine+"`""; Break }
			"UserName" {$QueryToRun += " AND UserName ContainsCIS `""+$UserName+"`""; Break }
			"EndpointName" {$QueryToRun += " AND EndpointName ContainsCIS `""+$EndpointName+"`""; Break }
			"ObjectType"  {$QueryToRun += " AND ObjectType = `""+$ObjectType+"`""; Break } 
			"ObjectType"  {$QueryToRun += " AND EventType = `""+$EventType+"`""; Break } 
			"DstPort"  {$QueryToRun += " AND DstPort = `""+$DstPort+"`""; Break } 
			Default {}
		}
	}
	$QueryToRun = $QueryToRun.Substring(5, $QueryToRun.Length-5)
	Write-Host "Completed query: " -NoNewline -ForegroundColor Green
	Write-Host $QueryToRun

	#Submitting queries first
	$submittedQueries = @{}
	
	$queryDetails = @{
		fromDate = $(Get-Date -Date $($(Get-Date -Date $fromDate).ToUniversalTime()) -Format O)
		toDate = $(Get-Date -Date $($(Get-Date -Date $toDate).ToUniversalTime()) -Format O)
		query = $QueryToRun;
		limit = $ResultSize;
		queryType = @("events");
		}
	$queryDetails = ConvertTo-Json -InputObject $queryDetails -Compress
	Write-Host
	foreach ($Name in $APITokenName)
	{
		Write-Host "Submitting Deep Visibility query using API token $Name"
		$submittedQueries.Add($Name, $api.submitDVQuery($Name, $queryDetails))
	}

	#Getting status
	$FinishedStatus = @{}
	$submittedQueriesCount = $submittedQueries.Count
	$SuccessfulFetch = ""
	$Return = @()
	while ($submittedQueriesCount -ne 0)
	{
		foreach ($Key in $submittedQueries.Keys)
		{
			if ($FinishedStatus[$Key].responseState -ne "FINISHED")
			{
			$FinishedStatus[$Key] = $api.getQueryStatus($Key, $submittedQueries[$Key])
			write-host "Checking query with API token $Key. Completed $($FinishedStatus[$Key].progressStatus)%, status $($FinishedStatus[$Key].responseState)"
			}
			else
			{
				$submittedQueriesCount--
				write-host "Query is ready for fetch with API token $Key" -ForegroundColor Green
				$Return += $API.GetQueryData($Key, $submittedQueries[$Key], $FetchSize)
				$SuccessfulFetch = $Key
			}
		}
		$submittedQueries.Remove($SuccessfulFetch)
	}
	return $Return
}

function Get-S1SitePolicy
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory, HelpMessage="Enter SentinelOne API token name", ValueFromPipelineByPropertyName)]
		[String] $APITokenName,

		[Parameter(HelpMessage="Full path to encrypted file to load API token")]
		[ValidateNotNullOrEmpty()]
		[String] $Path = $(Join-Path $env:APPDATA "SentinelOneAPI.token"),

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Int] $RetryIntervalSec = 5,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Int] $MaximumRetryCount = 2,

		[Parameter(Mandatory, ValueFromPipelineByPropertyName)]
		[String] $SiteId,

		[Parameter(ValueFromPipelineByPropertyName, DontShow)]
		[String] $SiteName
	)

	Begin
	{
		$API = [SentinelOne]::new($Path)
		$API.saveHTTPRetryParameters($RetryIntervalSec, $MaximumRetryCount)
		$SitePolicy = @()
	}
	Process
	{
		$API.CheckAPITokenName($APITokenName)
		if ($SitePolicy | Where-Object siteId -eq $SiteId)
		{
			#Site policy for this site has been already received
		}
		else
		{
			$SitePolicy += $api.GetS1SitePolicy($APITokenName, $SiteId, $SiteName)
		}
	}
	End
	{
		return $SitePolicy
	}
}

function Invoke-S1FileFetch
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory, HelpMessage="Enter SentinelOne API token name", ValueFromPipelineByPropertyName)]
		[String] $APITokenName,

		[Parameter(HelpMessage="Full path to encrypted file to load API token")]
		[ValidateNotNullOrEmpty()]
		[String] $Path = $(Join-Path $env:APPDATA "SentinelOneAPI.token"),

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Int] $RetryIntervalSec = 5,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Int] $MaximumRetryCount = 2,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Int] $DownloadTimeoutSec = 600,

		[Parameter(Mandatory, ValueFromPipelineByPropertyName)]
		[Alias("id")]
		[String] $AgentID,

		[ValidateNotNullOrEmpty()]
		[String] $Password = "Password123",

		[Parameter(Mandatory)]
		[String[]] $File,

		[Switch] $SaveEmptyFetch
	)

	Begin
	{
		$API = [SentinelOne]::new($Path)
		$API.saveHTTPRetryParameters($RetryIntervalSec, $MaximumRetryCount)
		$FetchCollection = @()
	}
	Process
	{
		Write-Host "Requesting fetch from agent $AgentID using API token $APITokenName. " -NoNewline
		$API.CheckAPITokenName($APITokenName)
		$FetchTime = (Get-Date).ToUniversalTime()
		$FetchResult = $API.RequestFileFetch($APITokenName, $AgentID, $File, $Password)
		if ($FetchResult -eq $true)
		{
			Write-Host "Fetch submitted" -ForegroundColor Green
		}
		else
		{
			Write-Host "Fetch failed to submit" -ForegroundColor Red
		}
		$FetchRequest = @{AgentID = $AgentID; APITokenName = $APITokenName; FetchTime = $FetchTime; FetchResult = $FetchResult; Downloaded = $false; FetchID = ""; ComputerName = ""; ScopeName = ""; SiteName = ""; SavedAs = ""}
		$FetchCollection += $FetchRequest
	}
	End
	{
		if ($FetchCollection.Count -eq 0)
		{
			Write-Host "No agents to fetch from (pipe input is empty)" -ForegroundColor Red
			return
		}
		Start-Sleep 3
		#Getting submission activity page per APITokenName
		Write-Host "Getting activity fetch logs..."
		foreach ($SuccessfullAPIToken in ($FetchCollection | Where-Object FetchResult -eq $true | Select-Object APITokenName | Get-Unique -AsString))
		{
			$ActivityPage += $api.RequestFileFetchActivityPage($SuccessfullAPIToken.APITokenName, 81)
		}
		#Getting fetch ID for all
		foreach ($FetchRequest in ($FetchCollection | Where-Object FetchResult -eq $true))
		{
			$ActivityEvent = $ActivityPage | Where-Object {($_.agentId -eq $FetchRequest.AgentID) -and ($(Get-Date -Date $_.createdAt) -gt $FetchRequest.FetchTime) -and ($_.APITokenName -eq $FetchRequest.APITokenName)}
			if ($ActivityEvent.Count -eq 1)
			{
				$FetchRequest.FetchID = $ActivityEvent.data.commandBatchUuid
				$FetchRequest.ComputerName = $ActivityEvent.data.computerName
				$FetchRequest.ScopeName = $ActivityEvent.data.scopeName
				$FetchRequest.SiteName = $ActivityEvent.data.siteName
			}
			else
			{
				Write-host "Multiple fetch events found for computer $($ActivityEvent.data.computerName | Select-Object -First 1)" -ForegroundColor Red
			}
		}
		#Trying to download submissions
		$StopTime = (Get-Date).AddSeconds($DownloadTimeoutSec)
		$AllDownloaded = $false
		Write-Host "Getting activity download logs..."
		while ($(Get-Date) -le $StopTime -and $AllDownloaded -eq $false)
		{
			#Count remaining files to download
			$RemainToDownload = ($FetchCollection | Where-Object {($_.FetchID -ne "") -and ($_.Downloaded -eq $false)}) | Measure-Object
			if ($RemainToDownload.Count -eq 0)
			{
				$AllDownloaded = $true
				break
			}
			Write-Host "$($RemainToDownload.Count) file(s) left to download. Waiting for file(s) upload..."
			Start-Sleep 5
			$ActivityPage = @()
			#Getting submission activity page per APITokenName
			foreach ($SuccessfullAPIToken in ($FetchCollection | Where-Object FetchResult -eq $true | Select-Object APITokenName | Get-Unique -AsString))
			{
				$ActivityPage += $API.RequestFileFetchActivityPage($SuccessfullAPIToken.APITokenName, 80)
			}
			#Downloading avaiable fetches
			foreach ($FetchRequest in ($FetchCollection | Where-Object {($_.FetchID -ne "") -and ($_.Downloaded -eq $false)}))
			{
				$ActivityEvent = $ActivityPage.data | Where-Object {$_.commandBatchUuid -eq $FetchRequest.FetchID}
				if ($ActivityEvent.Count -eq 1)
				{
					$FetchRequest.Downloaded = $true
					if ($API.RequestFileFetchDownload($FetchRequest.APITokenName, $ActivityEvent.downloadUrl, $ActivityEvent.filename, $SaveEmptyFetch) -eq $true)
					{
						$FetchRequest.SavedAs = $ActivityEvent.filename + ".zip"
					}
					else
					{
						$FetchRequest.SavedAs = "Not saved"
					}
				}
			}
		}
		$FetchCollection | Select-Object APITokenName, SiteName, ScopeName, ComputerName, Downloaded, SavedAs | Format-Table
		if($(Get-Date) -ge $StopTime)
		{
			Write-Host "Fetch timed out, most likely some agents are offline now." -ForegroundColor Red
		}
		Write-Host "Reminder: Password for fetched zip files: `"$Password`""
	}
}

