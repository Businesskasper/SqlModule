Import-Module -Name SqlModule

# Querying
ExecuteQuery -DatabaseServerInstance "localhost" `
    -DatabaseName "MyApp" `
    -Query "SELECT [UserName], [Email] FROM dbo.[AspNetUsers]" `
    # -SQLCredential ([PSCredential]::new("sa", (ConvertTo-SecureString -AsPlainText -Force -String "Passw0rd")))


# Writing
ExecuteNonQuery -DatabaseServerInstance "localhost" `
    -DatabaseName "MyApp" `
    -NonQuery "INSERT INTO dbo.[AspNetUsers] ([UserName], [Email]) VALUES('John.Doe@outlook.com', 'John.Doe@outlook.com')"


# Check if database exists
IsDatabasePresent -DatabaseServerInstance "localhost" -DatabaseName "MyApp"


# Kill all Database connections
KillDatabaseProcesses -DatabaseServerInstance "localhost" -DatabaseName "MyApp"


# Check if user has server login with sysadmin or db_owner role
IsUserDbAdmin -DatabaseServerInstance "localhost" -DatabaseName "MyApp" -UserType 'WindowsUser' -UserName "CONTOSO\Administrator"


# Get the latest database backup set
GetLatestBackup -DatabaseServerInstance "localhost" -DatabaseName "MyApp"


# Checks if the sql server (its running user) can access a provided path.
# Can be used prior to backing up a database to a network share.
CanSqlServerAccessPath -Path "\\share\folder\backuppath" -DatabaseServerInstance "localhost" -DatabaseName "MyApp"

# Back up database
BackupDatabase -DatabaseServerInstance "localhost" `
    -DatabaseName "MyApp" `
    -Destination "\\share\folder\backuppath\myapp.bak"


# Get the current backup status
# Can be used in a loop until "BackupDatabase", which runs async, is finnished
GetBackupStatus -DatabaseServerInstance "localhost" -DatabaseName "MyApp"


# Gets a database size without its log
GetDbNettoSize -DatabaseServerInstance "localhost" -DatabaseName "MyApp"