param()

######################FUNCTIONS######################
#https://github.com/TotalALM/VSTS-Tasks/blob/master/Tasks/Unzip/task/unzip.ps1
function UnZip($zipPath, $folderPath)
{
    Add-Type -Assembly "System.IO.Compression.FileSystem" ;
    [System.IO.Compression.ZipFile]::ExtractToDirectory("$zipPath", "$folderPath") ;
    
    Start-Sleep -m 4000
    
    If (Test-Path $zipPath){
	    Remove-Item $zipPath
    }
}
#https://github.com/TotalALM/VSTS-Tasks/blob/master/Tasks/Unzip/task/unzip.ps1
function RemoveZip($zip)
{ 
	Start-Sleep -m 4000
	If (Test-Path $zip){
		Remove-Item $zip -Recurse -Force
	}
}

function GetScanStatus($JsonData, $HubSession, $HubScanTimeout) 
{	
	#Start timer based on HubScanTimeout. If the scan has not completed in the specified amount of time, exit the script
	$Timeout = New-Timespan -Minutes $HubScanTimeout
	$SW = [Diagnostics.Stopwatch]::StartNew()
	
	while ($SW.Elapsed -lt $Timeout) {
		
		try {
			$ScanSummaryResponse = Invoke-RestMethod -Uri $JsonData._meta.href -Method Get -WebSession $HubSession
		}
		catch {
			Write-Error ("ERROR: {0}" -f $_.Exception.Response.StatusDescription)
			Exit
		}
		
		if ($ScanSummaryResponse.status -eq "COMPLETE") {
			Return
		}
		Else {
			Start-Sleep -Seconds 3
			Continue
		}
	}
	Write-Error ("ERROR: Hub Scan has timed out per configuration: {0} minutes" -f $HubScanTimeout)
	Exit
}

function CheckHubUrl($HubUrl)
{
	$HTTP_Request = [System.Net.WebRequest]::Create($HubUrl)
	$HTTP_Response = $HTTP_Request.GetResponse()
	
	If ([int]$HTTP_Response.StatusCode -eq 200) { 
		Write-Host "INFO: Communication with the Hub succeeded." 
		$HTTP_Response.Close()
	}
	Else {
		Write-Error "ERROR: Communication with the Hub failed. The server may be down, or the Server URL parameter is incorrect."
		$HTTP_Response.Close()
		Exit
	}
}
#####################################################
#Get Hub Url
$Service = (Get-VstsInput -Name BlackDuckHubService -Require)
$ServiceEndpoint = Get-VstsEndpoint -Name $Service
$HubUrl = $ServiceEndpoint.Url

#Get Hub Creds
$HubUsername = $ServiceEndpoint.auth.parameters.username
$HubPassword = $ServiceEndpoint.auth.parameters.password

$HubProjectName = Get-VstsInput -Name HubProjectName -Require
$HubRelease = Get-VstsInput -Name HubRelease -Require
$HubScanTarget = Get-VstsInput -Name HubScanTarget
$HubCodeLocationName = Get-VstsInput -Name HubCodeLocationName
$HubSetBuildStateOnPolicyViolation = Get-VstsInput -Name HubSetBuildStateOnPolicyViolation -Require
$HubBuildState = Get-VstsInput -Name HubBuildState
$HubGenerateRiskReport = Get-VstsInput -Name HubGenerateRiskReport -Require
$HubScanTimeout = Get-VstsInput -Name HubScanTimeout -Require
	
#Constants
$HostedCli = "download/scan.cli-windows.zip"
$ScanParent = "bds_hub_scanner"
$ScanChild = "scan.cli*"
$LogFolder = "bds_hub_logs"
$LogOutput = "CLI_Output.txt"
$HubScanScript = "scan.cli.bat"
$RiskReportFilename = "riskreport.json"
$PolicyState = ""

#Folder Locations
$HubScannerParentLocation = Join-Path $env:AGENT_HOMEDIRECTORY $ScanParent
$HubScannerChildLocation = Join-Path $HubScannerParentLocation $ScanChild
$HubScannerLogsLocation = Join-path $env:AGENT_HOMEDIRECTORY $LogFolder

#Remove trailing "/" from HubUrl if it exists
if (($HubUrl.Substring($HubUrl.Length-1) -eq "/")) { $HubUrl = $HubUrl.Substring(0, $HubUrl.Length-1) }

#Ensure HubURL is correct, and connectivity can be established. 
#No point in continuing if we can't connect to the Hub.
CheckHubUrl $HubUrl

#Establish Session
try {
	Invoke-RestMethod -Uri ("{0}/j_spring_security_check" -f $HubUrl) -Method Post -Body (@{j_username=$HubUsername;j_password=$HubPassword}) -SessionVariable HubSession -ErrorAction:Stop
}
catch {
	Write-Error ("ERROR: Could not establish session - Unauthorized")
	Exit
}

#Get Hub instance version number
$HubVersion = Invoke-RestMethod -Uri ("{0}/api/v1/current-version" -f $HubUrl) -Method Get -WebSession $HubSession
Write-Host ("INFO: Black Duck Hub {0}" -f $HubVersion)

#Determine if Hub scan client exists in the Agent home directory. If not, download it from the Hub instance.
if(!(Test-Path($HubScannerChildLocation)))
{
	Write-Host ("INFO: Hub scan client not found, create folder at: {0}" -f $HubScannerParentLocation)
	New-Item -ItemType directory -Path $HubScannerParentLocation | Out-Null
	$WC = New-Object System.Net.WebClient
	$CliUrl = ("{0}/{1}" -f $HubUrl, $HostedCli)
	$Filename = [System.IO.Path]::GetFileName($CliUrl)
	$Output = Join-Path $HubScannerParentLocation $Filename
	Write-Host ("INFO: Downloading Hub scan client from: {0}" -f $CliUrl)
	$WC.DownloadFile($CliUrl, $Output)
	
	if (Test-Path($Output)) { 
		Write-Host "INFO: Extracting Hub scan client"
		UnZip $Output $HubScannerParentLocation
	}
	else {
		Write-Error "ERROR: Error downloading Hub scan client"
		Exit
	}
}
else {
	
	$HubScanner = Get-ChildItem $HubScannerParentLocation | Where-Object {$_.PSIsContainer -eq $true -and $_.Name -match ("scan.cli-{0}" -f $HubVersion)}

	if (($HubScanner).Count -eq 0) {

		Write-Host "INFO: Newer Hub version detected, downloading updated scan client"

		$WC = New-Object System.Net.WebClient
		$CliUrl = ("{0}/{1}" -f $HubUrl, $HostedCli)
		$Filename = [System.IO.Path]::GetFileName($CliUrl)
		$Output = Join-Path $HubScannerParentLocation $Filename
		Write-Host ("INFO: Downloading Hub scan client from: {0}" -f $CliUrl)
		$WC.DownloadFile($CliUrl, $Output)

		if (Test-Path($Output)) { 
			Write-Host "INFO: Extracting Hub scan client"
			UnZip $Output $HubScannerParentLocation
		}
		else {
			Write-Error "ERROR: Error downloading Hub scan client"
			Exit
		}
	}
}

if (!(Test-Path($HubScannerLogsLocation)))
{
	Write-Host ("INFO: Create Hub logs folder at: {0}" -f $HubScannerLogsLocation)
	New-Item -ItemType directory -Path $HubScannerLogsLocation | Out-Null
}

$BuildLogFolder =[System.IO.Path]::Combine($HubScannerLogsLocation, $env:BUILD_DEFINITIONNAME, $env:BUILD_BUILDNUMBER)
if (!(Test-Path($BuildLogFolder)))
{
	Write-Host ("INFO: Create build specific Hub logs folder at: {0}" -f $BuildLogFolder)
	New-Item -ItemType directory -Path $BuildLogFolder | Out-Null
}

$HubScannerChildLocation = Join-Path $HubScannerParentLocation ("scan.cli-{0}" -f $HubVersion)
Write-Host ("INFO: Hub scan client found at: {0}" -f $HubScannerChildLocation)

#Get scan target
if ($HubScanTarget) {
	$ScanTarget = $HubScanTarget
} 
else { 
	$ScanTarget = $env:BUILD_SOURCESDIRECTORY
}

#Execute Hub scan and write logs (for some reason it comes through the error stream)
Write-Host "INFO: Starting Black Duck Hub scan with the following parameters"
Write-Host ("INFO: Server URL: {0}" -f $HubUrl)
Write-Host ("INFO: Project Location: {0}" -f $ScanTarget)
Write-Host ("INFO: Project Name: {0}" -f $HubProjectName)
Write-Host ("INFO: Project Version: {0}" -f $HubRelease)

#If a Code Location Name is specified, ensure the Hub is version 3.5.0 or later
if ([version]$HubVersion -ge [version]"3.5.0" -and $HubCodeLocationName) {
	Write-Host ("INFO: Code Location Name: {0}" -f $HubCodeLocationName)
	Start-Process -FilePath ("{0}\bin\{1}" -f $HubScannerChildLocation, $HubScanScript) `
	-ArgumentList ('-username {0} -password {1} -scheme {2} -host {3} -port {4} "{5}" -project "{6}" -release "{7}" -verbose -statusWriteDir "{8}" -name "{9}" -exclude /$tf/' -f `
	$HubUsername, $HubPassword, ([System.Uri]$HubUrl).Scheme, ([System.Uri]$HubUrl).Host, ([System.Uri]$HubUrl).Port, $ScanTarget, $HubProjectName, $HubRelease, $BuildLogFolder, $HubCodeLocationName) `
	-NoNewWindow -Wait -RedirectStandardError (Join-Path $BuildLogFolder $LogOutput)
}
else {
	if ([version]$HubVersion -lt [version]"3.5.0" -and $HubCodeLocationName) {
		Write-Host ("INFO: Code Location Name requires Hub 3.5.0+")
	}
	Start-Process -FilePath ("{0}\bin\{1}" -f $HubScannerChildLocation, $HubScanScript) `
	-ArgumentList ('-username {0} -password {1} -scheme {2} -host {3} -port {4} "{5}" -project "{6}" -release "{7}" -verbose -statusWriteDir "{8}" -exclude /$tf/' -f `
	$HubUsername, $HubPassword, ([System.Uri]$HubUrl).Scheme, ([System.Uri]$HubUrl).Host, ([System.Uri]$HubUrl).Port, $ScanTarget, $HubProjectName, $HubRelease, $BuildLogFolder) `
	-NoNewWindow -Wait -RedirectStandardError (Join-Path $BuildLogFolder $LogOutput)
}

#Get Hub scan status, and based on it, continue or exit
$status = ((Select-String -Path (Join-Path $BuildLogFolder $LogOutput) -Pattern "ERROR: ") -split ": ")[-1]

if ($status) {
	Write-Error "ERROR: " $status
}

$DataOutputFile = ((Select-String -Path (Join-Path $BuildLogFolder $LogOutput) -Pattern " Creating data output file: ") -split ": ")[-1]

if ($HubSetBuildStateOnPolicyViolation -eq "true") {
	Write-Host "INFO: Checking for Hub Policy Violations"
	
	#Re-establish Session
	try {
		Invoke-RestMethod -Uri ("{0}/j_spring_security_check" -f $HubUrl) -Method Post -Body (@{j_username=$HubUsername;j_password=$HubPassword}) -SessionVariable HubSession -ErrorAction:Stop
	}
	catch {
		Write-Error ("ERROR: {0}" -f $_.Exception.Response.StatusDescription)
		Exit
	}
	
	$JsonData = Get-Content -Raw -Path $DataOutputFile | ConvertFrom-Json
	
	#Get Scan Summary
	#Check for scan status and time out after a certain amount of minutes if status doesn't reach complete
	GetScanStatus $JsonData $HubSession $HubScanTimeout
	
	#Get Project/Version
	try {
		$ProjectVersionResponse = Invoke-RestMethod -Uri $JsonData._meta.links[0].href -Method Get -WebSession $HubSession
	}
	catch {
		Write-Error ("ERROR: {0}" -f $_.Exception.Response.StatusDescription)
		Exit
	}
	#Get Policy Status
	try {
		$PolicyResponse = Invoke-RestMethod -Uri ("{0}/policy-status" -f $ProjectVersionResponse.mappedProjectVersion) -Method Get -WebSession $HubSession
	}
	catch {
		Write-Error ("ERROR: {0}" -f $_.Exception.Response.StatusDescription)
		Exit
	}
	
	$PolicyStatus = $PolicyResponse.overallStatus
	switch ($PolicyStatus)
	{
		IN_VIOLATION { 
			$PolicyState = "IN_VIOLATION"
			Break
		} 
		NOT_IN_VIOLATION { 
			$PolicyState = "NOT_IN_VIOLATION"
			Break
		}
		IN_VIOLATION_OVERRIDDEN { 
			$PolicyState = "IN_VIOLATION_OVERRIDDEN"
			Break
		}
		default { 
			Write-Error "ERROR: Unknown error."
			Exit
		}
	}
	
}

if ($HubGenerateRiskReport -eq "true") {
	Write-Host "INFO: Generating Black Duck Risk Report"
	
	#Re-establish Session
	try {
		Invoke-RestMethod -Uri ("{0}/j_spring_security_check" -f $HubUrl) -Method Post -Body (@{j_username=$HubUsername;j_password=$HubPassword}) -SessionVariable HubSession -ErrorAction:Stop
	}
	catch {
		Write-Error ("ERROR: {0}" -f $_.Exception.Response.StatusDescription)
		Exit
	}

	$JsonData = Get-Content -Raw -Path $DataOutputFile | ConvertFrom-Json
	
	#Get Scan Summary
	#Check for scan status and time out after a certain amount of minutes if status doesn't reach complete
	GetScanStatus $JsonData $HubSession $HubScanTimeout
	
	#Get Project/Version
	try {
		$ProjectVersionResponse = Invoke-RestMethod -Uri $JsonData._meta.links[0].href -Method Get -WebSession $HubSession
	}
	catch {
		Write-Error ("ERROR: {0}" -f $_.Exception.Response.StatusDescription)
		Exit
	}

	#Get Aggregate BOM
	try {
		$BomResponse = Invoke-RestMethod -Uri ("{0}/components?limit=10000&sortField=riskProfile.categories.VULNERABILITY&ascending=true" -f $ProjectVersionResponse.mappedProjectVersion) -Method Get -WebSession $HubSession
	}
	catch {
		Write-Error ("ERROR: {0}" -f $_.Exception.Response.StatusDescription)
		Exit
	}

	if ($BomResponse.totalCount -gt 0) {

		$RiskReport = @()

		$TotalCount = $BomResponse.totalCount

		$Components = @()

		foreach ($Item in $BomResponse.items) {

			$ComponentName = $item.componentName
			$ComponentVersion = $item.componentVersionName

			$Licenses = @()

			foreach ($License in $Item.licenses.licenses) {
				$licenses += $license.licenseDisplay
			}

			$licenseName = $licenses -Join ", "

			foreach ($Count in $Item.securityRiskProfile.counts) {

				switch ($Count.countType)
				{
					HIGH { 
						$HighVulnCount = $Count.count
						Break
					} 
					MEDIUM { 
						$MediumVulnCount = $Count.count
						Break
					}
					LOW { 
						$LowVulnCount = $Count.count
						Break
					}
					default { 
						Break
					}
				}
			}
			
			$ComponentLink = ("{0}/#versions/id:{1}/view:overview" -f $HubUrl, ($Item.componentVersion -Split "/")[-1])

			$Components += [PSCUSTOMOBJECT]@{
				'component' = "$ComponentName";
				'version' = "$ComponentVersion"
				'license'="$LicenseName";
				'highVulnCount'="$HighVulnCount";
				'mediumVulnCount'="$MediumVulnCount";
				'lowVulnCount'="$LowVulnCount";
				'componentLink'= "$ComponentLink";
			}
		}
	}

	$ProjectVersion = $ProjectVersionResponse.mappedProjectVersion -Split "/"

	$RiskReport = [PSCUSTOMOBJECT]@{
		projectName = $HubProjectName
		projectLink = ("{0}/#projects/id:{1}" -f $HubUrl, $ProjectVersion[5])
		projectVersion = $HubRelease
		projectVersionLink = ("{0}/#versions/id:{1}" -f $HubUrl, $ProjectVersion[7])
		totalCount = $TotalCount
		components = $Components
	}

	$RiskReportFile = Join-Path $BuildLogFolder $RiskReportFilename
	$RiskReport | ConvertTo-Json -Compress | Out-File $RiskReportFile

	Write-Host "##vso[task.addattachment type=blackDuckRiskReport;name=riskReport;]$RiskReportFile"

}

#Set build state based on policy
if ($HubSetBuildStateOnPolicyViolation -eq "true") {

	switch ($HubBuildState)
	{
		Succeeded { 
			switch ($PolicyState)
			{
				IN_VIOLATION { 
					Write-Host "INFO: This release violates a Black Duck Hub policy, but the build state has been set to succeed on policy violtions" 
					Exit
				} 
				NOT_IN_VIOLATION { 
					Write-Host "INFO: This release has passed all Black Duck Hub policy rules." 
					Break
				}
				IN_VIOLATION_OVERRIDDEN { 
					Write-Host "INFO: This release has policy violations, but they have been overridden." 
					Break
				}
				default { 
					Write-Error "ERROR: Unknown error."
					Exit
				}
			}
		} 
		PartiallySucceeded { 
			switch ($PolicyState)
			{
				IN_VIOLATION { 
					Write-Warning "WARNING: This release violates a Black Duck Hub policy, but the build state has been set to partially succeed on policy violtions" 
					Write-Host "##vso[task.complete result=SucceededWithIssues;]"
					Break
				} 
				NOT_IN_VIOLATION { 
					Write-Host "INFO: This release has passed all Black Duck Hub policy rules." 
					Break
				}
				IN_VIOLATION_OVERRIDDEN { 
					Write-Host "INFO: This release has policy violations, but they have been overridden." 
					Break
				}
				default { 
					Write-Error "ERROR: Unknown error."
					Exit
				}
			}
		}
		Failed { 
			switch ($PolicyState)
			{
				IN_VIOLATION { 
					Write-Error "ERROR: This release violates a Black Duck Hub policy."  
					Write-Host "##vso[task.complete result=Failed;]"
					Break
				} 
				NOT_IN_VIOLATION { 
					Write-Host "INFO: This release has passed all Black Duck Hub policy rules." 
					Break
				}
				IN_VIOLATION_OVERRIDDEN { 
					Write-Host "INFO: This release has policy violations, but they have been overridden." 
					Break
				}
				default { 
					Write-Error "ERROR: Unknown error."
					Exit
				}
			}
		}
		default { 
			Break
		}
	}
}

Write-Host "INFO: Black Duck Hub Scan task completed"
Write-Host ("INFO: Logs can be found at: {0}" -f $BuildLogFolder)
