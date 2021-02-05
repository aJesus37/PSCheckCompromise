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


function Test-IOCs {

    Write-AndLog "[*] Starting IOC check on target host $hostname [*]" -Color "Yellow"
    Get-CFolder
    Test-Paths($paths)
    Test-Registry($registries)
    Test-Tasks($tasks)
    

}

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

function Test-Tasks($task_obj){

    Write-AndLog "  [+] Starting Scheduled Task check [+]" -Color "Yellow"

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

Test-IOCs

if((($pathsFound -ge $pesoPath) -And ($tasksFound -And $pesoTask) -And ($registriesFound -ge $pesoRegistry)) -Or ($pathsFound + $tasksFound + $registriesFound -ge $pesoTotal)) {
    Write-AndLog "`n[--] High chances of being compromised [--]" -Color "Red"
} else {
    Write-AndLog "`n[++] Low chance of compromise found [++]" -Color "Green"
}