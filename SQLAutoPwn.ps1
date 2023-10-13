$outdir="OUTPUT"
mkdir $outdir

echo '
------------------
SQLAutoPwn Loaded!
------------------

Commands you might want to run:


Just do everything automatically:

    Invoke-SQLAutoPwn-DoItAll [-csvfile <CSV File with Usernames and Passwords>]


Do it yourself discovery:

    $sql_servers = Invoke-SQLAutoDiscover

    -OR-

    $sql_servers = ( Get-Content ".\sql_servers.csv" | ConvertFrom-CSV )


Do it yourself access checks/vuln scans:

    Invoke-SQLAutoPwn-Single -sql_servers $sql_servers

    Invoke-SQLAutoPwn-Bulk -sql_servers $sql_servers -csvfile .\creds.csv
'


# Function used to remove characters from a string that might be problematic if used as filenames.
function Remove-UnsafeChars($inputString) {
    $inputString.replace('?','Q').replace('*','S').replace(':','C').replace('|','P').replace('!','E').replace('#','H').replace('$','D').replace('``','T').replace('"','q').replace("'",'s').replace('+','p').replace(',','c').replace('\','b').replace('/','f').replace(')','R').replace('(','L').replace('<','l').replace('>','g').replace('[','R').replace(']','r')
}


function Invoke-SQLAutoDiscover {
    # Discover SQL servers by querying Active Directory.
    $sql_servers = ( Get-SQLInstanceDomain -Verbose | ConvertTo-CSV | Add-Content ( $outdir + "\Discovery--Active_Directory.csv" ) -PassThru | ConvertFrom-CSV )

    # Discover SQL servers via UDP broadcast.
    $sql_servers += ( Get-SQLInstanceBroadcast -Verbose | ConvertTo-CSV | Add-Content ( $outdir + "\Discovery--UDP_Broadcast.csv" ) -PassThru | ConvertFrom-CSV )

    $sql_servers | ConvertTo-CSV | Add-Content ( $outdir + "\SQL_Discovery--All.csv" )
    echo ( "Discovered " + [string]$sql_servers.Count + "SQL servers.")

    return $sql_servers
}


function Invoke-SQLAutoPwn-DoItAll {
    Param
    (
        [Parameter(Mandatory=$false, Position=0)]
        [string] $csvfile
    )
 
    # Discover SQL servers.
    $sql_servers = Invoke-SQLAutoDiscover

    # Attempt login to all servers with default credentials.
    echo "Checking servers for access with default credentials..."
    $sql_servers | Get-SQLServerLoginDefaultPw -Verbose | convertto-csv | add-content ( $outdir + "\Vulnerability_Report--Default_Credentials.csv" ) -Encoding Ascii -PassThru | convertfrom-csv
    echo ""
    echo "INFO: You will need to manually run additional scans with any default credentials that were found!"
    echo "---"

    # Execute Invoke-SQLAutoPwn-Single as the currently logged in user.
    Invoke-SQLAutoPwn-Single -sql_servers $sql_servers

    # Execute Invoke-SQLAutoPwn-Single as the currently logged in user.
    if ($csvfile) {
        Invoke-SQLAutoPwn-Bulk -sql_servers $sql_servers -csvfile $csvfile
    }
}


# Run all PowerUpSQL checks against a single user credential.
# Uses the currently logged-in user account if username and password are not specified.
function Invoke-SQLAutoPwn-Single {

    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        $sql_servers,
        [Parameter(Mandatory=$false, Position=1)]
        [string] $username,
        [Parameter(Mandatory=$false, Position=2)]
        [string] $password
    )

    # Gather username and password from input, if specified, for use in PowerUpSQL cmdlet calls.
    $cred_params = @{}
    $output_label = ( "_CurrentUser__" + $env:USERNAME )
    $cred_pair = ( "Currently logged in user (" + $env:USERNAME + ")" )

    if ( $username -and $password ) { 
        $cred_params = @{ Username=$username; Password=$password }

        # Make a filename-safe version of the strings used in output names
        $safe_password = ( Remove-UnsafeChars $password )
        $safe_username = ( Remove-UnsafeChars $username )

        $output_label = ( $safe_username + "__" + $safe_password )
        $cred_pair = ( $username + ":" + $password )
    }


    # Start actions with this user...
    echo ""
    echo "---"
    echo ( "Starting tests with creds: " + $cred_pair + "..." )

    
    # Test access to every SQL server. Log successes to file in the output folder.
    echo ( "- Testing access to SQL servers..." )

    $tested_servers = ( $sql_servers | Get-SQLConnectionTestThreaded -Verbose -Threads 10 @cred_params )

   
    # For each accessible SQL server that was found...
    $targets = $null
    $targets = ( $tested_servers | Where-Object {$_.Status -like "Accessible"} )

    # Log the number of accessible servers available to each user tested.
    echo ( [string]$targets.count + ',"' + $username + '","' + $password + '"' ) | Add-Content ( $outdir + "\Summary--Users_and_Accessible_Servers_Count.csv" ) -Encoding ASCII

    # Create a unique output folder where output is saved.
    # Will look like:
    #     OUTPUT\[count]_[username]__[password]
    #
    #     OUTPUT\5__CurrentUser__mallen3
    #     OUTPUT\10_acme-jsmith__P---w0rd
    #
    $userdir = ( [string]$targets.count + "_" + $output_label )
    mkdir ( $outdir + "\" + $userdir )

    # Log tested and accessible servers
    $tested_servers | ConvertTo-Csv | Add-Content ( $outdir + "\" + $userdir + "\SQL_Servers--Full_list_tested.csv" )
    $targets | ConvertTo-Csv | Add-Content ( $outdir + "\" + $userdir + "\SQL_Servers--Accessible.csv" )


    if ( $targets.count -le 0 ) {
        echo "- No accessible SQL servers identified."
    } else {

        # Perform a vulnerability scan, and save the output in a subdirectory of $outdir.
        echo "- Executing SQL audit on each accessible server..."

        $auditdir = ( $outdir + "\" + $userdir + "\Audit_Output" )
        mkdir $auditdir
        $targets | Invoke-SQLAudit @cred_params -Verbose -OutFolder $auditdir


        # Log all non-default databases in $outdir.
        echo "- Logging accessible databases on each accessible server..."

        $targets | Get-SQLDatabaseThreaded @cred_params -Verbose -Threads 10 -NoDefaults | ConvertTo-CSV | Add-Content ( $outdir + "\" + $userdir + "\Non-Default_Databases_Accessed.csv" )


        #Get general server information such as SQL/OS versions, service accounts, sysdmin access etc.	Get information from a single server
        #Note: Running this against domain systems can reveal where Domain Users have sysadmin privileges.
        $targets | Get-SQLServerInfoThreaded @cred_params -Verbose | ConvertTo-CSV | Add-Content ( $outdir + "\" + $userdir + "\Server_Info.csv" )


        #Get an inventory of common objects from the remote server including permissions, databases, tables, views etc, and dump them out into CSV files.
        #$targets | Invoke-SQLDumpInfo -Verbose 


        #Find sensitive data based on column name	
        $targets | Get-SQLColumnSampleDataThreaded –Verbose –Threads 10 –Keyword "credit,ssn,password,hash" –SampleSize 2 –ValidateCC –NoDefaults | ConvertTo-CSV | Add-Content ( $outdir + "\" + $userdir + "\Sensitive_Data_Samples.csv" )
    }

    # Rename the output folder, so that users with access to more servers are easily identifiable.
    echo "Done checking this user."

}


# Run all PowerUpSQL checks against all users in listed in a CSV file containing Username and Password pairs.
# The CSV file MUST have column headers: Username and Password
# SQL users -OR- Domain users can be specified in the CSV file. Just prepend domain users with domain name like: DOMAIN\USERNAME
function Invoke-SQLAutoPwn-Bulk {

    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        $sql_servers,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $csvfile
    )

    if ( $csvfile -ne $null ) {
        $cred_pairs = get-content $csvfile | convertfrom-csv
    }

    # Execute Invoke-SQLAutoPwn-Single as every user in the specified CSV file.
    $cred_pairs | foreach {
        Invoke-SQLAutoPwn-Single -username $_.Username -password $_.Password -sql_servers $sql_servers
    }

}

