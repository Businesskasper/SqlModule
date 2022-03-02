enum UserType {

    WindowsUser
    SqlUser
}

function ImportSqlModule {

    try {

        Import-Module SqlServer -DisableNameChecking -ErrorAction SilentlyContinue
        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
    }
    catch [Exception] { }

    try {

        $serverObj = [Microsoft.SqlServer.Management.Smo.Server]::new()
    }
    catch [Exception] {

        throw [Exception]::new("Das SQL Modul konnte nicht geladen werden. Bitte installieren Sie das Powershell Modul `"SqlServer`".", $_.Exception)
    }
}


function GetSqlConnection([string]$DatabaseServerInstance, [string]$DatabaseName, [PSCredential]$SQLCredential) {

    ImportSqlModule

    $sqlConnection = [Microsoft.SqlServer.Management.Smo.Server]::new($DatabaseServerInstance)
    $sqlConnection.ConnectionContext.DatabaseName = $DatabaseName

    if ($SQLCredential -ne $null) {

        $sqlConnection.ConnectionContext.LoginSecure = $false
        $sqlConnection.ConnectionContext.Login = $SQLCredential.UserName
        $sqlConnection.ConnectionContext.set_SecurePassword($SQLCredential.Password)
    }

    return $sqlConnection
}


<#
Überprüft ob die angegebene Datenbank verfügbar ist.
#>
function IsDatabasePresent([string]$DatabaseServerInstance, [string]$DatabaseName, [PSCredential]$SQLCredential = $null) {

    $sqlConnection = GetSqlConnection -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -SQLCredential $SQLCredential
    
    try {

        $sqlConnection.ConnectionContext.Connect()
        return $sqlConnection.ConnectionContext.IsOpen
    }
    catch [Exception] {

        return $false
    }
    finally {

        $sqlConnection.ConnectionContext.Disconnect()
    }
}


<#
Schließt alle Verbindungen zur angegebenen Datenbank.
#>
function KillDatabaseProcesses ([string]$DatabaseServerInstance, [string]$DatabaseName, [PSCredential]$SQLCredential = $null) {

    $sqlConnection = GetSqlConnection -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -SQLCredential $SQLCredential
    $sqlConnection.ConnectionContext.ConnectTimeout = 500
    $sqlConnection.ConnectionContext.StatementTimeout = 65534
            
    try {

        $sqlConnection.ConnectionContext.Connect()
        
        $db = $sqlConnection.Databases.Where({$_.Name -eq $DatabaseName})[0]
        if ($db -ne $null) {

            $sqlConnection.KillAllProcesses($DatabaseName)
        }
    }
    catch [Exception] {

        throw
    }
    finally {

        $sqlConnection.ConnectionContext.Disconnect()
    }
}


<#
Führt eine Query aus und gibt die Ergebnisse als [PSCustomObject[]] aus.
#>
function ExecuteQuery([string]$Query, [string]$DatabaseServerInstance, [string]$DatabaseName, [PSCredential]$SQLCredential = $null) {

    $sqlConnection = GetSqlConnection -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -SQLCredential $SQLCredential
 
    try {

        $sqlConnection.ConnectionContext.Connect()
        $reader = $sqlConnection.ConnectionContext.ExecuteReader($Query)

        $results = @()

        while ($reader.Read()) {

            $result = New-Object -TypeName PSCustomObject

            for ($i = 0; $i -lt $reader.FieldCount; $i++) { 

                $value = $reader.GetValue($i)
                if ($value -is [String]) {

                    $value = $value.ToString()
                }

                $result | Add-Member -MemberType NoteProperty -Name $reader.GetName($i) -Value $value
            }
            
            $results += $result
        }

        return $results
    }
    catch [Exception] {

        $ex = $_.Exception
        while ($null -ne $ex.InnerException) {

            $ex = $ex.InnerException
        }

        throw $ex
    }
    finally {

        try {

            $reader.Dispose()
            $sqlConnection.ConnectionContext.Disconnect()
        }
        catch [Exception] {}
    }

}


<#
Führt ein Statement aus und gibt die Anzahl der bearbeiteten Zeilen zurück.
#>
function ExecuteNonQuery([string] $NonQuery, [string] $DatabaseServerInstance, [string] $DatabaseName, [PSCredential]$SQLCredential = $null) {

    $sqlConnection = GetSqlConnection -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -SQLCredential $SQLCredential
 
    try {

        $sqlConnection.ConnectionContext.Connect()
        $sqlConnection.ConnectionContext.ExecuteNonQuery($NonQuery)
    }
    catch [Exception] {

        $ex = $_.Exception
        while ($null -ne $ex.InnerException) {

            $ex = $ex.InnerException
        }

        throw $ex
    }
    finally {

        try {

            $sqlConnection.ConnectionContext.Disconnect()
        }
        catch [Exception] {}
    }
}


<#
Prüft ob ein User einen Sql Login und db_owner Rechte auf Datenbankebene oder sysadmin bzw. serveradmin Rechte auf Serverebene hat.
#>
function IsUserDbAdmin([string]$UserName, [string]$DatabaseServerInstance, [string]$DatabaseName, [UserType]$UserType, [PSCredential]$SQLCredential = $null) {

    if ($UserType -eq [UserType]::WindowsUser) {

        $type = "= 'U'"

        $user = [System.Security.Principal.NTAccount]::new($UserName)
        $sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).value

        $sqlSidBytes = SqlModule\ExecuteQuery -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -Query "
    
            SELECT SID_BINARY(N'$($sid)') AS SqlSid;
        " | select -ExpandProperty SqlSid

        $sqlSidString = "0X" + [BitConverter]::ToString($sqlSidBytes).Replace("-", "")

        # Groß - / Kleinschreibung beim Usernamen ignorieren
        $UserNameFromSql = SqlModule\ExecuteQuery -Query "SELECT [name] FROM master.sys.server_principals WHERE [type] = 'U' AND [sid] = $($sqlSidString)" -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -SQLCredential $SQLCredential | select -ExpandProperty name

        if ($null -eq $sqlSidBytes -or [String]::IsNullOrWhiteSpace($sqlSidBytes) -or [String]::IsNullOrWhiteSpace($UserNameFromSql)) {

            try {

                return (SqlModule\ExecuteQuery -DatabaseServerInstance $DatabaseServerInstance -DatabaseName master -SQLCredential $SQLCredential -Query "
                
                    EXECUTE AS LOGIN = N'$($UserName)';
                    SELECT HAS_DBACCESS('$($DatabaseName)') as HasAccess
                " | select -ExpandProperty HasAccess) -eq 1
            }
            catch {

                return $false
            }
        }
        else {

            $UserName = $UserNameFromSql
        }
    }
    elseif ($UserType -eq [UserType]::SqlUser) {

        $type = "= 'S'"
    }


    $query = "

        DECLARE @hasLogin tinyint;
        SET @hasLogin = 0;
        DECLARE @hasAccess tinyint;
        SET @hasAccess = 0;
        DECLARE @userName nvarchar(max);
        SET @userName = '$($UserName)'

        if (SELECT 1 FROM master.sys.server_principals WHERE [type] $($type) AND name = @userName AND [is_disabled] = 0) = 1
        BEGIN
	        SET @hasLogin = 1
        END

        IF @hasLogin = 1
        BEGIN
	        IF IS_ROLEMEMBER ('db_owner',@userName) = 1
	        BEGIN
		        SET @hasAccess = 1;
	        END

	        IF (@hasAccess = 0)
	        BEGIN
		        IF IS_SRVROLEMEMBER ('sysadmin',@userName) = 1
		        BEGIN
			        SET @hasAccess = 1;
		        END
	        END

	        IF (@hasAccess = 0)
	        BEGIN
		        IF IS_SRVROLEMEMBER ('serveradmin',@userName) = 1
		        BEGIN
			        SET @hasAccess = 1;
		        END
	        END
        END
        SELECT @hasAccess AS 'HasAccess'
    "

    $hasAccess = SqlModule\ExecuteQuery -Query $query -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -SQLCredential $SQLCredential | select -ExpandProperty HasAccess

    return $hasAccess -eq 1
}


function GetLatestBackup([string]$DatabaseServerInstance, [string]$DatabaseName, [PSCredential]$SQLCredential = $null) {
    
    $query = "
    SELECT TOP(1)
        msdb.dbo.backupset.database_name AS DatabaseName,  
        CAST(ROUND(msdb.dbo.backupset.backup_size / (1024*1024), 0) AS numeric(38,0)) AS SizeInMB,
        CAST(ROUND(msdb.dbo.backupset.compressed_backup_size / (1024*1024), 0) AS numeric(38,0)) AS CompressedSizeInMB,
        CONVERT(datetime, msdb.dbo.backupset.backup_finish_date) AS BackupDate
    FROM   msdb.dbo.backupmediafamily  
       INNER JOIN msdb.dbo.backupset ON msdb.dbo.backupmediafamily.media_set_id = msdb.dbo.backupset.media_set_id  
    WHERE  msdb..backupset.type = 'D' AND msdb.dbo.backupset.database_name = '$($DatabaseName)'
    ORDER BY  
       BackupDate DESC
    "

    $latestBackup = SqlModule\ExecuteQuery -Query $query -DatabaseServerInstance $DatabaseServerInstance -DatabaseName "master" -SQLCredential $SQLCredential | select -First 1

    return $latestBackup
}


function CanSqlServerAccessPath([string]$Path, [string]$DatabaseServerInstance, [PSCredential]$SQLCredential = $null) {

    $query = "
        -- Enable xp_cmdshell stored procedure
        exec sp_configure 'show advanced options', 1
        reconfigure
        exec sp_configure 'xp_cmdshell', 1
        reconfigure
        exec sp_configure 'show advanced options', 0
        reconfigure

        DECLARE @output INT
        EXEC @output = xp_cmdshell 'DIR `"$($Path)`" /B', NO_OUTPUT

        IF @output = 1
	        SELECT 0 AS CanAccess
        ELSE
	        SELECT 1 AS CanAccess

        -- Disable xp_cmdshell stored procedure
        exec sp_configure 'show advanced options', 1
        reconfigure
        exec sp_configure 'xp_cmdshell', 0
        reconfigure
        exec sp_configure 'show advanced options', 0
        reconfigure
    "

    return [bool](SqlModule\ExecuteQuery -Query $query -DatabaseServerInstance $DatabaseServerInstance -DatabaseName "master" -SQLCredential $SQLCredential | select -ExpandProperty CanAccess)
}


function BackupDatabase([string]$Destination, [string]$DatabaseServerInstance, [string]$DatabaseName, [PSCredential]$SQLCredential = $null) {

    $sqlConnection = GetSqlConnection -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -SQLCredential $SQLCredential
    $sqlConnection.ConnectionContext.ConnectTimeout = 500
    $sqlConnection.ConnectionContext.StatementTimeout = 65534
            
   
    try {
        
        # Verbinden und Verbindungen zur Datenbank trennen
        $sqlConnection.ConnectionContext.Connect()
        $sqlConnection.KillAllProcesses($DatabaseName)

        # Backup erstellen
        $backup = [Microsoft.SqlServer.Management.Smo.Backup]::new()
        $backup.Action = [Microsoft.SqlServer.Management.Smo.BackupActionType]::Files
        $backup.Database = $DatabaseName
        $backup.Devices.Add([Microsoft.SqlServer.Management.Smo.BackupDeviceItem]::new($Destination, [Microsoft.SqlServer.Management.Smo.DeviceType]::File))
        $backup.CompressionOption = [Microsoft.SqlServer.Management.Smo.BackupCompressionOptions]::On

        $stopwatch = [System.Diagnostics.Stopwatch]::new()
        $stopwatch.Start()
        
        $backup.SqlBackupAsync($sqlConnection)

        $rounds = 0
        Write-Progress -Activity "Backup `"$($DatabaseName)`" auf `"$($DatabaseServerInstance)`"" -Status "0%" -PercentComplete 0
        while ($backup.AsyncStatus.ExecutionStatus -eq [Microsoft.SqlServer.Management.Smo.ExecutionStatus]::InProgress)
        {
            if ($rounds % 2 -eq 0) {

                $backupOperation = SqlModule\GetBackupStatus -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -SQLCredential $SQLCredential
                if ($null -ne $backupOperation) {

                    Write-Progress -Activity "Backup `"$($DatabaseName)`" auf `"$($DatabaseServerInstance)`"" -Status "$([Math]::Round($backupOperation.PercentComplete, 0))%" -PercentComplete $backupOperation.PercentComplete
                }
            }

            Start-Sleep -Seconds 2
            $rounds ++
        }
        $stopwatch.Stop()

        if (-not ($backup.AsyncStatus.ExecutionStatus -eq [Microsoft.SqlServer.Management.Smo.ExecutionStatus]::Succeeded)) {
        
            throw [Exception]::new("Backup of Database $($DatabaseName) on $($DatabaseServerInstance) failed.", $backup.AsyncStatus.LastException)
        }      
    }
    catch [Exception] {

        $sqlConnection.ConnectionContext.Disconnect()   

        while (Test-Path $Destination) {

            Remove-Item -Path $Destination -ErrorAction SilentlyContinue
        }

        $ex = $_.Exception
        while ($null -ne $ex.InnerException) {

            $ex = $ex.InnerException
        }

        throw $ex
    }
    finally {

        Write-Progress -Activity "Backup `"$($DatabaseName)`" auf `"$($DatabaseServerInstance)`"" -Completed
        $sqlConnection.ConnectionContext.Disconnect()
    }
}


function GetBackupStatus([string]$DatabaseServerInstance, [string]$DatabaseName, [PSCredential]$SQLCredential = $null) {

    $runningBackupQuery = "
        SELECT 
	        dbs.[name] AS DatabaseName,
	        r.percent_complete AS PercentComplete, 
	        dateadd(second,estimated_completion_time/1000, getdate()) as EstimatedCompletionTime
        FROM 
	        sys.dm_exec_requests r INNER JOIN master.sys.databases dbs ON dbs.database_id = r.database_id
	        CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) a
        WHERE r.command in ('BACKUP DATABASE') AND dbs.[name] = '$($DatabaseName)'
   "

   return (SqlModule\ExecuteQuery -Query $runningBackupQuery -DatabaseServerInstance $DatabaseServerInstance -DatabaseName "master" -SQLCredential $SQLCredential | select -First 1)
}


function GetDbNettoSize([string]$DatabaseServerInstance, [string]$DatabaseName, [PSCredential]$SQLCredential = $null) {
    
    # Größe der SQL Dateien ohne Log auslesen
    $dbSizeQuery = "

        SELECT DISTINCT
            (SUM(m.size) OVER (PARTITION BY d.name))* 8/1024 AS 'TotalDbSizeMB'
        FROM 
            sys.master_files m 
            INNER JOIN sys.databases d ON d.database_id = m.database_id
        WHERE 
            DB_NAME(d.database_id) = '$($databaseName)' AND 
            type = 0"
        
    $dbSizeString = SqlModule\ExecuteQuery -Query $dbSizeQuery -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -SQLCredential $SQLCredential | select -ExpandProperty TotalDbSizeMB
    $dbSize = [double]0
    [double]::TryParse($dbSizeString, [ref]$dbSize) | Out-Null

    # Nicht genutzten Speicherplatz auslesen
    $dbSizeAvailableSpaceMBString = SqlModule\ExecuteQuery -Query "EXEC sp_spaceused" -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -SQLCredentials $SQLCredential | select -ExpandProperty "unallocated space"
    $dbSizeAvailableSpaceMB = [double]0
    [double]::TryParse($dbSizeAvailableSpaceMBString.Replace("MB", "").Replace(".", ","), [Ref] $dbSizeAvailableSpaceMB) | Out-Null

    # Nettodatenbankgröße bestimmen
    $dbSize = $dbSize - $dbSizeAvailableSpaceMB

    return $dbSize
}


function GetTopTablesBySize([int]$TableCount, [string]$DatabaseServerInstance, [string]$DatabaseName, [PSCredential]$SQLCredential = $null) {

    $largeTablesQuery = "

        SELECT TOP ($($TableCount))
            t.name AS TableName,
            s.name AS SchemaName,
            p.rows AS RowCounts,
            SUM(a.total_pages) * 8 AS TotalSpaceKB, 
            SUM(a.used_pages) * 8 AS UsedSpaceKB, 
            (SUM(a.total_pages) - SUM(a.used_pages)) * 8 AS UnusedSpaceKB
        FROM 
            sys.tables t
            INNER JOIN sys.indexes i ON t.object_id = i.object_id
            INNER JOIN sys.partitions p ON i.object_id = p.object_id AND i.index_id = p.index_id
            INNER JOIN sys.allocation_units a ON p.partition_id = a.container_id
            LEFT OUTER JOIN sys.schemas s ON t.schema_id = s.schema_id
        WHERE 
            t.name NOT LIKE 'dt%' 
            AND t.is_ms_shipped = 0
            AND i.object_id > 255 
        GROUP BY 
            t.name, s.name, p.rows
        ORDER BY 
            UsedSpaceKB DESC
    "

    return (SqlModule\ExecuteQuery -Query $largeTablesQuery -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -SQLCredential $SQLCredential)
}


function GetLocalDrivesFreeSpace([string]$DatabaseServerInstance, [PSCredential]$SQLCredential = $null) {

    $dbDriveSpaceQuery = "

        SELECT 
            DISTINCT dovs.logical_volume_name AS LogicalName,
            SUBSTRING(dovs.volume_mount_point,1,1) AS Drive,
            CONVERT(INT,dovs.available_bytes/1048576.0) AS FreeSpaceInMB
        FROM 
            sys.master_files mf
        CROSS APPLY 
            sys.dm_os_volume_stats(mf.database_id, mf.FILE_ID) dovs
        ORDER BY 
            FreeSpaceInMB ASC
    "

    return (ExecuteQuery -DatabaseServerInstance $DatabaseServerInstance -SQLCredential $SQLCredential -DatabaseName 'master' -Query $dbDriveSpaceQuery)
}