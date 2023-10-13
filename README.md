# SQLAutoPwn

***Automated execution of the excellent [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)\* tool.***

*\*[PowerUpSQL sold separately.](https://github.com/NetSPI/PowerUpSQL)*

---

## Example Usage (Automatic)

1. Import PowerUpSQL and `SQLAutoPwn.ps1` into the same PowerShell process.

```
import-module .\PowerUpSQL.ps1

import-module .\SQLAutoPwn.ps1
```

2. Run everything all at once with `Invoke-SQLAutoPwn-DoItAll`.
	- If you have any credentials you want to supply in addition to the currently logged in user, include them in a CSV file with the `csvfile` flag.

```
Invoke-SQLAutoPown-DoItAll -csvfile .\creds.csv
```

The command above will do all of the following actions:

1. Discover SQL servers by querying Active Directory.
2. Discover SQL servers via UDP broadcast.
3. Check all discovered SQL servers for login with default credentials.
4. Check all discovered SQL servers for access with the currently logged in Windows user account.
5. Check all discovered SQL servers for access with the credentials specified in the CSV file.
6. If access is granted with the currently logged in user or user credentials in the CSV file, the following actions are taken with each user and server:
	1. Check the SQL server for vulnerabilities with `Invoke-SQLAudit`.
	2. Log all non-default databases that are accessible on the server.
	3. Log various details about the server (`Get-SQLServerInfoThreaded`).
	4. Log any databases that appear to contain sensitive data based on keywords found in column names.
7. All data is logged to the `.\OUTPUT` folder in which the script is executed.
	1. Subfolders are created for each user account tested. To make identification of highly privileged accounts easier, the subfolder naming convention for each user is:

```
<Number of SQL Servers Accessible>_<Domain-Username>__<Password>
```

Passwords are included in the folder name in case you are testing a single username with multiple different passwords.
- ***BE SURE TO REMOVE DUPLICATE ENTRIES FROM YOUR CSV FILE, SO YOU DON'T LOCK OUT ACCOUNTS!!***

The currently logged in user's password is not included in their folder name. Instead, the username is prepended with `_CurrentUser__`. That way it will (hopefully) appear at the top of the list.

The final output directory structure should look something like:

```
OUTPUT\
OUTPUT\1__CurrentUser__jsmith
OUTPUT\5_dbuser__P4ssw0rd
OUTPUT\9_dbadmin__Adm1nP4ssw0rd
```

---

## Manual Usage

If you want to execute individual actions yourself, other commands are available:

- Launch automated discovery only:

```
$sql_servers = Invoke-SQLAutoDiscover
```

- Import discovered servers from saved PowerUpSQL output. 

```
$sql_servers = ( Get-Content ".\sql_servers.csv" | ConvertFrom-CSV )
```

- Execute all tests for the currently logged in user only.

```
Invoke-SQLAutoPwn-Single -sql_servers $sql_servers
```

- Execute all tests with credentials listed in the CSV file only.

```
Invoke-SQLAutoPwn-Bulk -sql_servers $sql_servers -csvfile .\creds.csv
```

---

## Providing credentials in a CSV file

Credential pairs can be provided as a CSV file with the headings `Username` and `Password`.
- Domain users or database users can be specified. Just prefix domain users with their domain name, as in `DOMAIN\username`.

Example:

```csv
"Username","Password"
"jsmith","myp@$$w0rd"
"acme\jwilliams","Summer20XX!"
```

