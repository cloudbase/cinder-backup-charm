# Copyright 2016 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

Import-Module JujuHelper
Import-Module JujuHooks
Import-Module JujuUtils
Import-Module JujuWindowsUtils
Import-Module OpenStackCommon

# HELPER functions

$POSIX_BACKEND = "cinder.backup.drivers.posix.PosixBackupDriver"
$SUPPORTED_BACKUP_DRIVERS = @(
    $POSIX_BACKEND
)

function Get-SMBShareContext {
    $requiredCtxt = @{
        "share" = $null
    }
    $ctxt = Get-JujuRelationContext -Relation "smb-share" -RequiredContext $requiredCtxt
    if(!$ctxt.Count) {
        return @{}
    }
    return $ctxt
}

function Get-ADCredentialsFromCinderBackupContext {
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true)]
        [Hashtable]$Context
    )
    if ($Context.Count -eq 0) {
        return $null
    }
    $username = $Context["ad_user"]

    $password = $Context["ad_password"]
    $securePassword = ConvertTo-SecureString -AsPlainText -Force $password
    $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
    return $credential
}

function Get-CinderBackupContext {
    $requiredCtxt =  @{
        "ad_user" = $null;
        "ad_password" = $null;
        "ad_group" = $null;
        "ad_domain" = $null;
    }
    $ctxt = Get-JujuRelationContext -Relation "cinder-backup" -RequiredContext $requiredCtxt
    if(!$ctxt.Count) {
        return @{}
    }
    return $ctxt
}

function Get-CharmConfigContext {
    $ctxt = Get-ConfigContext
    $backupDriver = $ctxt["backup_backend"]
    $backupPosixPath = $ctxt["backup_posix_path"]

    if($backupDriver -notin $SUPPORTED_BACKUP_DRIVERS) {
        # This option is mandatory and must be set correctly.
        Set-JujuStatus -Status blocked -Message ("Unsupported backend driver {0}" -f @($backupDriver))
        return @{}
    }

    if ($backupDriver -eq $POSIX_BACKEND -and [string]::IsNullOrEmpty($backupPosixPath) -eq $false) {
        # backup-posix-path is not mandatory, as that value may be
        # supplied by a relation to a chrm that implements the$ScriptBlock

        $backupCtxt = Get-CinderBackupContext
        if ($backupCtxt.Count -gt 0){
            $creds = Get-ADCredentialsFromCinderBackupContext $backupCtxt
            # Test that the cinder user has access rights to the configured share.
            # We need to use CredSSP.
            $canAccess = Invoke-Command -Credential $creds -Authentication Credssp -ComputerName . -ScriptBlock {
                return (Test-Path $using:backupPosixPath)
            }
            if ($canAccess -eq $false) {
                # User explicitly set a backup path, but we were unable to access it.
                # We only throw an error here when we have the cinder-backup context
                # because at that point we are sure that this node is already a part
                # of active-directory. That means we should be able to access the share
                # supplied by the user, without fail.
                Set-JujuStatus -Status blocked -Message "Failed to access $backupPosixPath"
                return @{}
            }
        }
    }
    return $ctxt
}

function Get-PosixBackendConfig {
    [CmdletBinding()]
    Param(
        [parameter(mandatory=$true)]
        [Hashtable]$ConfigCtx,
        [parameter(mandatory=$true)]
        [Hashtable]$SmbContext
    )

    $backupDir = $ConfigCtx["backup_posix_path"]
    if (!$backupDir) {
        if ($SmbContext.Count -eq 0) {
            Set-JujuStatus -Status blocked -Message "No backup destination configured"
            Write-JujuWarning "smb-share context not ready"
            return
        }
        $backupDir = $SmbContext["share"]
    }

    if (!$backupDir) {
        Write-JujuWarning "no backup destination configured"
        return
    }

    $tplCtx = [System.Collections.Generic.Dictionary[string, object]](New-Object "System.Collections.Generic.Dictionary[string, object]")

    $tplCtx["backup_driver"] = $POSIX_BACKEND
    $tplCtx["backup_posix_path"] = $backupDir

    return (Start-RenderTemplate -Context $tplCtx -TemplateName "posix_backend.tpl")
}

function Get-CinderBackupConfigSnippet {
    $cfgCtx = Get-CharmConfigContext
    if ($cfgCtx.Count -eq 0) {
        Write-JujuWarning "config context not ready"
        return
    }

    $backupCtx = Get-CinderBackupContext
    if ($backupCtx.Count -eq 0) {
        Write-JujuWarning "cinder-backup context not yet ready"
        return
    }

    $smbShareCtx = Get-SMBShareContext
    $backend = $cfgCtx["backup_backend"]

    switch($backend){
        $POSIX_BACKEND {
            return (Get-PosixBackendConfig -ConfigCtx $cfgCtx -SmbContext $smbShareCtx)
        }
        default {
            # If we get here, we failed during validation of config
            Throw "Invalid cinder backup backend $backend"
        }
    }
}

function Enable-ClientCredSSP {
    $ctxt = Get-CinderBackupContext
    if ($ctxt.Count -eq 0) {
        Write-JujuWarning "cinder-backup context not yet ready"
        return
    }
    $domainName = $ctxt["ad_domain"]
    Enable-WSManCredSSP -Role "Client" -DelegateComputer "*.$domainName" -Force | Out-Null
}

# HOOK functions

function Invoke-ConfigChangedHook {
    Enable-ClientCredSSP
    $backupConfig = Get-CinderBackupConfigSnippet
    if (!$backupConfig) {
        Write-JujuWarning "Backup config not yet ready"
        return
    }

    $relationData = @{
        "cinder_backup_config" = $backupConfig;
    }

    $rids = Get-JujuRelationIds -Relation 'cinder-backup'
    foreach ($rid in $rids) {
        Set-JujuRelation -RelationId $rid -Settings $relationData
    }
    Set-JujuStatus -Status active -Message "Unit is ready"
}

function Invoke-SMBShareRelationJoinedHook {
    $backupCtx = Get-CinderBackupContext
    if ($backupCtx.Count -eq 0){
        Write-JujuWarning "cinder-backup context not yet ready."
        return
    }

    $cfgCtx = Get-ConfigContext
    if($cfgCtx.Count -eq 0) {
        Write-JujuWarning "config context not yet ready"
        return
    }

    $accounts = @(
        $backupCtx["ad_group"],
        $backupCtx["ad_user"]
    )
    
    $marshalledAccounts = Get-MarshaledObject -Object $accounts
    $settings = @{
        "share-name" = $cfgCtx["share_name"]
    }
    $rids = Get-JujuRelationIds -Relation "smb-share"
    foreach ($rid in $rids) {
        Set-JujuRelation -RelationId $rid -Settings $settings
    }
}

# END hook functions
