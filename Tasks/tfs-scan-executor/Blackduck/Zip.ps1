#https://github.com/TotalALM/VSTS-Tasks/blob/master/Tasks/Unzip/task/unzip.ps1
function UnZip($zipPath, $folderPath) {
    Add-Type -Assembly "System.IO.Compression.FileSystem" ;
    [System.IO.Compression.ZipFile]::ExtractToDirectory("$zipPath", "$folderPath") ;
    
    Start-Sleep -m 4000
    
    If (Test-Path $zipPath){
        Remove-Item $zipPath
    }
}

#https://github.com/TotalALM/VSTS-Tasks/blob/master/Tasks/Unzip/task/unzip.ps1
function RemoveZip($zip) { 
    Start-Sleep -m 4000
    If (Test-Path $zip){
        Remove-Item $zip -Recurse -Force
    }
}
