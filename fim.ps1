# File Integrity Monitor
# Compatible w/ PowerShell 2.0-4.0 (win7,2008,2012,etc)
# Written: Lee Mazzoleni


function alertGen {
    $activeUser = $($(qwinsta.exe | findstr Active) -split "\s+")[1]
    $detectedTime = Get-Date -Format u
    #could also add the most recently logged in user by parsing out last 4624 event ID
    if($activeUser) {
        $event = -join$('ALERT:','"Change Detected" TimeDetected:"',$detectedTime,'" FIMdir:"',$FIMdir,'" ChangedProperties:"',$discrepancies,'" ActiveUser(s):"',$activeUser,'"')
    } else {
        $event = -join$('ALERT:','"Change Detected" TimeDetected:"',$detectedTime,'" FIMdir:"',$FIMdir,'" ChangedProperties:"',$discrepancies,'" ActiveUser(s):"n/a"')
    }
    #log the event locally before shipping to SIEM
    $event >> $logFile
}


function doFimCheck {
        #make sure there are at least two lines in the log file to compare
        $lineCount = Get-Content $logFile | Measure-Object
        $lineCount = $lineCount.Count
        #if there are enough lines to compare, proceed.
        if ($lineCount -ge 2) {
            #save the most recently written line, retrieve its alias and use it to locate the second-most recently written log entry with that alias
            $newLine = Get-Content $logFile | select -Index $($lineCount - 1);
            $alias = $newLine.split('"')[3];
            Get-Content $logFile | Where-Object { $_.split('"')[3] -eq $alias } >> $tempFile;
            $tempLineCount =  Get-Content $tempFile | Measure-Object
            $tempLineCount = $tempLineCount.Count
            #make sure there are at least two entries from the current alias in the temp file, (if the config file is altered, will start comparisons after 2nd cycle).
            if ($tempLineCount -ge 2) {            
                $baseLine = Get-Content $tempFile | select -Index $($tempLineCount - 2)
                $newLine = Get-Content $tempFile | select -Index $($tempLineCount - 1)
                $FIMdir = $($newLine -split '"')[3]
                $dataIndices = @{ 5 = "LastAccessed"; 7 = "LastWritten"; 9 = "TotalChildren"; 11 = "SubFolders"; 13 = "OtherFiles" };
                $discrepancies = ""
                foreach ($key in $dataIndices.keys) {
                    #-join $('The key is ',$key,' and its corresponding value is ',$dataIndices[$key])
                    $oldData = $($baseLine -split '"')[$key]
                    $newData = $($newLine -split '"')[$key]
                    if ($newData -ne $oldData) {
                        #-join $('ALERT:"Change detected to Monitored Directory" FIMdir:"',$FIMdir,'" Old',$dataIndices[$key],':"',$oldData,'" New',$dataIndices[$key],':"',$newData,'"')
                        $discrepancies += $dataIndices[$key] + ','
                    }
                }
                if ($discrepancies.ToCharArray().Count -gt 0) {
                    $discrepancies = $discrepancies -replace '.{1}$'
                    alertGen
                }
            Remove-Item $tempFile
            }
        }
}


function getFim {
        $dirs = @()
        foreach ($folder in ($dirList)) {
            $alias = [System.Text.Encoding]::UTF8.GetBytes($folder);
            $alias = [System.Convert]::ToBase64String($alias);
            $lastWrite = $(Get-ItemProperty -Path "$folder" -Name LastWriteTime).LastWriteTime;
            $lastAccess = $(Get-ItemProperty -Path "$folder" -Name LastAccessTime).LastAccessTime;
            $dirs = Get-ChildItem -Recurse "$folder" | Where-Object { $_.Attributes -eq 'Directory' } | Measure-Object;
            $dirs = $dirs.Count;
            #"THE COUNT OF SUBFOLDERS IS $dirs"
            if ($dirs -eq 0 -or !$dirs) {
                $dirs = "0"
            }
            $children = $(Get-ChildItem -Recurse "$folder") | Measure-Object;
            $children = $children.Count;
            if ($children -eq 0 -or !$children) {
                $children = "0";
            }  
            $fileCount = $children - $dirs;    
            $timeChecked = Get-Date -Format u
            $fim = -join $('Hostname:"',$hostName,'" FIMDirectory:"',$alias,'" LastAccessed:','"',$lastAccess,'" LastWritten:"',$lastWrite,'" TotalChildren:"',$children,'" Subfolders:"',$dirs,'" OtherFiles:"',$fileCount,'" TimeChecked:"',$timeChecked,'"');
            $fim >> "$logFile";
            doFimCheck;
        }
}


$configFile = "C:\Users\testuser\Desktop\Testing\config.txt"
$logFile = "C:\Users\testuser\Desktop\Testing\fim-log.txt"
$tempFile = "C:\Users\testuser\Desktop\Testing\tempfile.txt"
$time = Get-Date
$hostName = $(HOSTNAME.EXE) -replace "`n|`r"
$dirList = @()
Get-Content $configFile | ForEach-Object {
        if ($_[0] -ne '#') { 
            Get-ChildItem "$_" | Out-Null
            if ($? -eq 'True') {
                $dirList += $_
            }
        }
}

getFim