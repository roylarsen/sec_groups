<#
.SYNOPSIS

Take a username and a path and give the security groups a user might need
.PARAMETER path

path is the path to the folder a user needs access to. Quote the path. Use path, not a drive.
.PARAMETER user

user is the username. first.last format. No need to quote these. 
.EXAMPLE

sec_groups.ps1 -path  '\\path\with\space in\name' -user roy.larsen
Works
.EXAMPLE
sec_groups.ps1 -path  "\\path\with\space in\name" -user roy.larsen
Works
.EXAMPLE
sec_groups.ps1 -path \\path\with\space in\name\ -user roy.larsen
Wont Work
#>
param(
    [string]$path, #= $(throw "-path is required"),
    [string]$user
)

$toadd = @()

if($path[0] -like "Y"){
    $path = $path.split(":")[1]
    $path = "<path root every share uses>$path"
} 

while($path -notlike "<path root that everyone shares>""){

    $acl = (Get-Acl $path).Access | % {Write-Output $_.IdentityReference} | Where-Object {$_ -like "<domain prefix>"} #This gets all the domain groups from the current $path

    foreach($group in $acl){
        try{
            $throwaway = get-aduser $group.ToString().Split("\")[1] #done to catch users with explicit permissions
        }Catch{
            if(Get-ADGroupMember $group.ToString().Split("\")[1] -recursive | % {$_.SamAccountName} | Where-Object {$_ -like $user}){
                break #We're good if we find the user in a group
            }else{
                if($toadd -contains $group.ToString().Split("\")[1]){
                    break #we're good if a the group list has the group already
                }else{
                    $toadd += "$path - $group"
                }
            }
        }Finally{
            if($group -like "*$user"){
                #intentially left blank
            }
        }

    }
    $path = Split-Path $path
}
$toadd
