param([String]$LogName=".\IOC-Logs",[Int]$pesoPath=1,[Int]$pesoRegistry=1,[Int]$pesoTask=1,[Int]$pesoTotal=2)

$datetime= Get-Date -Format "dd-MM-yy-hh-mm-ss"
$hostname = $(hostname)

# Checks for compromise on the following aspects: Scheduled tasks, FileSystem Paths and Registry

######### IOC's assignment. Populate the content below, inside the @" "@ tags, separated one by line

#Define the paths here, one by line
# E.g: "C:\Windows\suspiciousdir\file.dll"
$paths=@"
"@

#Define the registries here, one by line
# The format is \PATH\TO\HIVE\PropertyName
$registries=@"
"@

#Define the scheduled task names here, one by line
$tasks=@"
"@

# Tranform above data into a parseable list to powershell
[System.Array]$paths = $paths.split("`n") | ? {$_ -ne ""}
[System.Array]$registries = $registries.split("`n") | ? {$_ -ne ""}
[System.Array]$tasks = $tasks.split("`n") | ? {$_ -ne ""}

[Int]$global:pathsFound=0;
[Int]$global:tasksFound=0;
[Int]$global:registriesFound=0;

##########################################

# Function to colorfully log the output to the screen, and also to a log file
function Write-AndLog(){
        Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $text,
         [Parameter(Mandatory=$false, Position=1)]
         [string] $Color="White"
    )
    $time = Get-Date -Format "dd/MM/yyyy hh:mm:ss"

    "[$time]$text" | % {Write-Host "$_" -ForegroundColor $color; Out-File -FilePath "$LogName`_$hostname`_$datetime.txt" -Append -InputObject $_}
}


# Main function, only calls the others.
function Test-IOCs {

    Write-AndLog "[*] Starting IOC check on target host $hostname [*]" -Color "Yellow"
    Get-CFolder
    Test-Paths($paths)
    Test-Registry($registries)
    Test-Tasks($tasks)
    

}


# Check if the given paths (files or folders) exists in the system
function Test-Paths($paths_obj){
    Write-AndLog "  [+] Starting Path check [+]" -Color "Yellow"
    foreach ($path in $paths_obj) {
        if (Test-Path -Path $path){
            Write-AndLog "      [-] The path ""$path"" exists [-]" -Color "Red"
            $global:pathsFound+=1;
        } else {
            Write-AndLog "      [+] The path ""$path"" doesn't exists [+]" -Color "Green"
        }
    }

}


#Check for the existence of registry properties in given registry hives
function Test-Registry($reg_obj){
    Write-AndLog "  [+] Starting Registry check [+]" -Color "Yellow"
    foreach ($registry in $reg_obj) {
        $path = (Split-Path $registry)
        $property = (Split-Path $registry -Leaf)

        if (Test-Path -Path "Registry::$path"){
            if (Get-Item -Path "Registry::$path" | Select-Object -ExpandProperty Property | ? {$_ -match "$property"}){
                $global:registriesFound+=1;
                Write-AndLog "      [-] The registry ""$registry"" exists [-]" -Color "Red"
            } else {
            Write-AndLog "      [+] The registry ""$registry"" doesn't exists [+]" -Color "Green"
            } 
        } 
        
    }

}

# Check if the given scheduled tasks exists in the system
function Test-Tasks($task_obj){

    Write-AndLog "  [+] Starting Scheduled Task check [+]" -Color "Yellow"

    #schtasks.exe was used to be compatible with Powershell 2.0 (Windows 7), since it doesn't have Get-ScheduledTask by default 
    $tasks = schtasks.exe /query /fo csv | Convertfrom-csv | Select-Object -Property N* -ExpandProperty N*

    foreach ($task in $task_obj){
        $task_match=($tasks | ? { $_ -match "^.*\\$task$"})
        if ($task_match){
            $global:tasksFound+=1;
            Write-AndLog "      [-] The scheduled task ""$task"" exists, $task_match [-]" -Color "Red"
        } else {
            Write-AndLog "      [+] The scheduled task ""$task"" doesn't exists [+]" -Color "Green"
        }
    }
}


# Displays content of the C:\ and C:\ Folders, listing only directories (hidden or not)
function Get-CFolder(){

    Write-AndLog "  [+] Listing folders in C:\ and C:\Temp[+]" -Color "Yellow"

    $folders=Get-ChildItem "C:\" -Force | ?{ $_.PSIsContainer } | Out-String
    Write-AndLog "$folders" -Color "White"

    try {
        $tempFolders=Get-ChildItem "C:\Temp" -Force 2>$null | ?{ $_.PSIsContainer }  | Out-String
        Write-AndLog "$tempFolders" -Color "White"
    
    } catch{
        Write-AndLog "Folder C:\Temp doesn't exist in this machine`n" -Color "White"
    }

    
   
}

# Calls the main function
Test-IOCs

# Makes a calculus based on the amount of IOCs found. If the total is greater than $pesoTotal, or if all the individual are greater or equal to the specific type, it will conclude that there are high chances of compromise.
if((($pathsFound -ge $pesoPath) -And ($tasksFound -And $pesoTask) -And ($registriesFound -ge $pesoRegistry)) -Or ($pathsFound + $tasksFound + $registriesFound -ge $pesoTotal)) {
    Write-AndLog "`n[--] High chances of being compromised [--]" -Color "Red"
} else {
    Write-AndLog "`n[++] Low chance of compromise found [++]" -Color "Green"
}