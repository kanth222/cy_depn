#ObjectName	ObjectFolder	SafeName	PlatformID	DependencyAddress	DependencyType	DependencyName	TaskFolder


$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath

$LOG_FILE_PATH = "$ScriptLocation\Dependencies_Onboarding_Utility.log"

$URL_PVWAAPI = $PVWAURL + "/api"
$URL_Authentication = $URL_PVWAAPI + "/auth"
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + "/Logoff"

# @FUNCTION@ ======================================================================================================================
# Name...........: Open-FileDialog
# Description....: Opens a new "Open File" Dialog
# Parameters.....: LocationPath
# Return Values..: Selected file path
# =================================================================================================================================
Function Open-FileDialog {
	<# 
.SYNOPSIS 
	Opens a new "Open File" Dialog
.DESCRIPTION
	Opens a new "Open File" Dialog
.PARAMETER LocationPath
	The Location to open the dialog in
#>
	param (
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
		[ValidateNotNullOrEmpty()] 
		[string]$LocationPath
	)
	Begin {
		[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
		$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
	}
	Process {
		$OpenFileDialog.initialDirectory = $LocationPath
		$OpenFileDialog.filter = "CSV (*.csv)| *.csv"
		$OpenFileDialog.ShowDialog() | Out-Null
	}
	End {
		return $OpenFileDialog.filename
	}
}
#endregion


#region Log Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
Function Write-LogMessage {
	<# 
.SYNOPSIS 
	Method to log a message on screen and in a log file
.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
	param(
		[Parameter(Mandatory = $true)]
		[AllowEmptyString()]
		[String]$MSG,
		[Parameter(Mandatory = $false)]
		[Switch]$Header,
		[Parameter(Mandatory = $false)]
		[Switch]$SubHeader,
		[Parameter(Mandatory = $false)]
		[Switch]$Footer,
		[Parameter(Mandatory = $false)]
		[ValidateSet("Info", "Warning", "Error", "Debug", "Verbose")]
		[String]$type = "Info"
	)
	try {
		If ($Header) {
			"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "======================================="
		} ElseIf ($SubHeader) { 
			"------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "------------------------------------"
		}
	
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		$writeToFile = $true
		# Replace empty message with 'N/A'
		if ([string]::IsNullOrEmpty($Msg)) {
			$Msg = "N/A" 
  }
		# Mask Passwords
		if ($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()\[\]\-\\\/]+))') {
			$Msg = $Msg.Replace($Matches[2], "****")
		}
		# Check the message type
		switch ($type) {
			"Info" { 
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t$Msg"
				break
			}
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor Yellow
				$msgToWrite += "[WARNING]`t$Msg"
				break
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
				break
			}
			"Debug" { 
				if ($InDebug) {
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
				} else {
					$writeToFile = $False 
				}
				break
			}
			"Verbose" { 
				if ($InVerbose) {
					Write-Verbose $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
				} else {
					$writeToFile = $False 
				}
				break
			}
		}
		
		If ($writeToFile) {
			$msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH 
  }
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "======================================="
		}
	} catch {
		Write-Error "Error in writing log: $($_.Exception.Message)" 
 }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Join-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Join-ExceptionMessage {
	<# 
.SYNOPSIS 
	Formats exception messages
.DESCRIPTION
	Formats exception messages
.PARAMETER Exception
	The Exception object to format
#>
	param(
		[Exception]$e
	)

	Begin {
	}
	Process {
		$msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
		while ($e.InnerException) {
			$e = $e.InnerException
			$msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
		}
		return $msg
	}
	End {
	}
}
#endregion


function Set-FileCategory {
    param (
        $safeName,
        $file,
        $category,
        $value
    )

    try {
        Add-PVFileCategory -safe $safeName -folder Root -file $fileName -category $category -value $value -ErrorAction Stop
    }
    catch {
        Set-PVFileCategory -safe $safeName -folder Root -file $fileName -category $category -value $value -ErrorAction Stop
    }
}

#main

If ([string]::IsNullOrEmpty($CsvPath)) {
	$CsvPath = Open-FileDialog($g_CsvDefaultPath)
}
$delimiter = $(If ($CsvDelimiter -eq "Comma") {
		"," 
	} else {
		"`t" 
 } )
$accountsCSV = Import-Csv $csvPath -Delimiter $delimiter

$rowCount = $($accountsCSV.Safe.Count)
$counter = 0
$csvLine = 0 # First line is the headers line

Foreach ($account in $accountsCSV){

    if($null -ne $account){
    
        $csvLine++

        try{

            $safeName = $account.SafeName
            $dependencyName = $account.DependencyName
            $policyId = ""

            Open-PVSafe -safe $safeName

            Add-PVPasswordObject -file $dependencyName -password (" " | ConvertTo-SecureString -Force -AsPlainText) -safe $safeName

            Set-FileCategory -category MasterPassName -value $account.ObjectName -safe $safeName -folder Root -file $dependencyName
            Set-FileCategory -category MasterPassFolder -value Root -safe $safeName -folder Root -file $dependencyName

            Switch ($account.DependencyType) {
            "Windows Service" {
            
                Set-FileCategory -category PolicyId -value "WinServ" -safe $safeName -folder Root -file $dependencyName
                Set-FileCategory -category address -value $account.DependencyAddress -safe $safeName -folder Root -file $dependencyName
                
            }
            "Scheduled Task"  {
                
                Set-FileCategory -category PolicyId -value "SchTask" -safe $safeName -folder Root -file $dependencyName
                Set-FileCategory -category address -value $account.DependencyAddress -safe $safeName -folder Root -file $dependencyName
                Set-FileCategory -category TaskFolder -value "/" -safe $safeName -folder Root -file $dependencyName
            }
            "IIS Pool" {$policyId = "IISPool"}
            
            }

            Set-FileCategory -category PolicyId -value INIFile -safe $safeName -folder Root -file $dependencyName


            
        }
        catch {
			Write-LogMessage -Type Info -MSG "Skipping onboarding account $($dependencyName) (CSV line: $csvLine) into the Password Vault. Error: $(Join-ExceptionMessage $_.Exception)"
		}
    
    }

}
