param()

Write-Host "BEGINNING NEW TFS SCRIPT !!!!!!!!!!!!!!!!"
######################LIBRARIES######################

Import-Module $PSScriptRoot\Blackduck\Zip.ps1
Import-Module $PSScriptRoot\Blackduck\ScanStatus.ps1

######################SETTINGS#######################

#Utilize TLS 1.2 for this session
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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
$HubSetBuildStateOnPolicyViolation = Get-VstsInput -Name HubSetBuildStateOnPolicyViolation
$HubBuildState = Get-VstsInput -Name HubBuildState
$HubGenerateRiskReport = Get-VstsInput -Name HubGenerateRiskReport
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
if (($HubUrl.Substring($HubUrl.Length-1) -eq "/")) {
    $HubUrl = $HubUrl.Substring(0, $HubUrl.Length-1) 
}

#Ensure HubURL is correct, and connectivity can be established. 
#No point in continuing if we can't connect to the Hub.
#CheckHubUrl $HubUrl

#Establish Session
try {
    Invoke-RestMethod -Uri ("{0}/j_spring_security_check" -f $HubUrl) -Method Post -Body (@{j_username=$HubUsername;j_password=$HubPassword}) -SessionVariable HubSession -ErrorAction:Stop
}
catch {
    Write-Error ("ERROR: Could not establish session - Unauthorized")
    Exit
}

#Get scan target
if ($HubScanTarget) {
    $ScanTarget = $HubScanTarget
} 
else { 
    $ScanTarget = $env:BUILD_SOURCESDIRECTORY
}

#Ensure scan target exists
if (-Not (Test-Path $ScanTarget)) {
    Write-Error ("ERROR: Scan target {0} does not exist" -f $ScanTarget)
}

#Execute Hub scan and write logs (for some reason it comes through the error stream)
Write-Host "INFO: Starting Black Duck Hub scan with the following parameters"
Write-Host ("INFO: Server URL: {0}" -f $HubUrl)
Write-Host ("INFO: Project Location: {0}" -f $ScanTarget)
Write-Host ("INFO: Project Name: {0}" -f $HubProjectName)
Write-Host ("INFO: Project Version: {0}" -f $HubRelease)

#Set BD_HUB_PASSWORD environment variable
$env:BD_HUB_PASSWORD = $HubPassword

#Write Powershell related environment variables
$Env:DETECT_JAR_PATH = $HubScannerParentLocation

#Create detect argument list
Write-Host "Creating Detect Arguments"
Write-Host $ScanTarget.GetType()
$ScanTarget = $ScanTarget.ToString()
Write-Host $ScanTarget.GetType()
$DetectArguments =  @("--detect.source.path", $ScanTarget)
Write-Host $DetectArguments.GetType()

$JavaArgs = @("-jar", "BLAH")
Write-Host $JavaArgs.GetType()
$AllArgs =  $JavaArgs + $DetectArguments
Write-Host $AllArgs.GetType()
Write-Host "Running detect: $AllArgs"

$DetectProcess = Start-Process java -ArgumentList $AllArgs -NoNewWindow -PassThru

Invoke-RestMethod https://blackducksoftware.github.io/hub-detect/hub-detect.ps1?$(Get-Random) | Invoke-Expression;

#Download Detect from the Web
try {

} catch {
    #Write-Warning ("WARNING: Failed to download the latest detect script from the web. Using the last deployed version.")
	#Import-Module $PSScriptRoot\Blackduck\Detect.ps1
}

#Invoke Detect
Detect @DetectArguments

Exit 

#Get Hub scan status, and based on it, continue or exit
$status = ((Select-String -Path (Join-Path $BuildLogFolder $LogOutput) -Pattern "ERROR: ") -split ": ")[-1]

if ($status) {
    Write-Error ("ERROR: Exception in scan log output")
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
        
        Write-Error ("ERROR: Exception checking hub connection for policy violations")
        Write-Error -Exception $_.Exception -Message "Exception occured checking hub connection for policy violations."
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
        Write-Error ("ERROR: Exception getting project version")
        Write-Error ("ERROR: {0}" -f $_.Exception.Response.StatusDescription)
        Exit
    }
    #Get Policy Status
    try {
        $PolicyResponse = Invoke-RestMethod -Uri ("{0}/policy-status" -f $ProjectVersionResponse.mappedProjectVersion) -Method Get -WebSession $HubSession
    }
    catch {
        Write-Error ("ERROR: Exception getting policy status")
        Write-Error -Exception $_.Exception -Message "Exception occured getting policy status."
        Write-Error ("ERROR: {0}" -f $_.Exception.Response.StatusDescription)
        Exit
    }
	
    $PolicyStatus = $PolicyResponse.overallStatus
    switch ($PolicyStatus) {
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
        Write-Error ("ERROR: Exception checking hub connection for risk report")
        Write-Error -Exception $_.Exception -Message "Exception occured checking hub connection for risk report."
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
        Write-Error ("ERROR: Exception getting project version for risk report")
        Write-Error -Exception $_.Exception -Message "Exception occured getting project version for risk report."
        Write-Error ("ERROR: {0}" -f $_.Exception.Response.StatusDescription)
        Exit
    }

    #Get Aggregate BOM
    try {
        $BomResponse = Invoke-RestMethod -Uri ("{0}/components?limit=10000&sortField=riskProfile.categories.VULNERABILITY&ascending=true" -f $ProjectVersionResponse.mappedProjectVersion) -Method Get -WebSession $HubSession
    }
    catch {
        Write-Error ("ERROR: Exception getting aggregate BOM for risk report")
        Write-Error -Exception $_.Exception -Message "Exception occured getting aggregate BOM for risk report."
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

                switch ($Count.countType) {
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
			
            $ComponentId = ($Item.component -Split "/")[-1]
            $ComponentVersionId = ($Item.componentVersion -Split "/")[-1]

            #Get component version policy status
            if ($ComponentVersionId) {
                $ComponentPolicyResponse = Invoke-RestMethod -Uri ("{0}/components/{1}/versions/{2}/policy-status" -f $ProjectVersionResponse.mappedProjectVersion, $ComponentId, $ComponentVersionId) -Method Get -WebSession $HubSession
                $ComponentLink = ("{0}/#versions/id:{1}/view:overview" -f $HubUrl, $ComponentVersionId)
            }
            else {
                #Component/version could not be found
                $ComponentPolicyResponse = Invoke-RestMethod -Uri ("{0}/components/{1}/policy-status" -f $ProjectVersionResponse.mappedProjectVersion, $ComponentId) -Method Get -WebSession $HubSession
                $ComponentLink = ("{0}/#projects/id:{1}" -f $HubUrl, $ComponentId)
                $ComponentVersion = "?"
                $LicenseName = "License Not Found"
            }

            $ComponentPolicyStatus = $ComponentPolicyResponse.approvalStatus

            $Components += [PSCUSTOMOBJECT]@{
                'component' = "$ComponentName";
                'version' = "$ComponentVersion"
                'license'="$LicenseName";
                'policyStatus'="$ComponentPolicyStatus"
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
    Write-Host "INFO: Generated black duck risk report"
    Write-Host ("INFO: File at {0}" -f $RiskReportFile)
}

#Set build state based on policy
if ($HubSetBuildStateOnPolicyViolation -eq "true") {

    switch ($HubBuildState) {
        Succeeded { 
            switch ($PolicyState) {
                IN_VIOLATION { 
                    Write-Host "INFO: This release violates a Black Duck Hub policy, but the build state has been set to succeed on policy violtions" 
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
        PartiallySucceeded { 
            switch ($PolicyState) {
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
            switch ($PolicyState) {
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

Write-Host "INFO: Finished running."

PhoneHome $HubUrl $HubVersion $HubUsername $HubPassword

Write-Host "INFO: Black Duck Hub Scan task completed"
Write-Host ("INFO: Logs can be found at: {0}" -f $BuildLogFolder)
