function GetScanStatus($JsonData, $HubSession, $HubScanTimeout) {	
    #Start timer based on HubScanTimeout. If the scan has not completed in the specified amount of time, exit the script
    $Timeout = New-Timespan -Minutes $HubScanTimeout
    $SW = [Diagnostics.Stopwatch]::StartNew()
	
    while ($SW.Elapsed -lt $Timeout) {
		
        try {
            $ScanSummaryResponse = Invoke-RestMethod -Uri $JsonData._meta.href -Method Get -WebSession $HubSession
        }
        catch {
            Write-Error ("ERROR: Exception checking scan status")
            Write-Error -Exception $_.Exception -Message "Exception occured getting scan url."
            Write-Error ("RESPONSE: {0}" -f $_.Exception.Response)
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
