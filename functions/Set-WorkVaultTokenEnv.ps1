function Set-WorkVaultTokenEnv {
    <#
    .SYNOPSIS
        Получает Vault token через LDAP auth-метод и записывает его в $env:VAULT_TOKEN.
    .EXAMPLE
        Set-WorkVaultTokenEnv -VaultAddr 'https://vault.contoso.test'
    .EXAMPLE
        Set-WorkVaultTokenEnv -VaultAddr 'https://vault.contoso.test' -Credential $cred
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^https?://')]
        [string]$VaultAddr,

        [Parameter(Mandatory)]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [string]$AuthMount = 'ldap',

        [Parameter()]
        [switch]$SkipCertificateCheck
    )

    begin {
        $ErrorActionPreference = 'Stop'
    }

    process {
        [string]$loginUser = $Credential.UserName -replace '@.*$'
        [string]$password = $Credential.GetNetworkCredential().Password

        [string]$uri = "{0}/v1/auth/{1}/login/{2}" -f $VaultAddr.TrimEnd('/'), $AuthMount, [System.Uri]::EscapeDataString($loginUser)
        [string]$body = @{ password = $password } | ConvertTo-Json

        [hashtable]$irmParams = @{
            Uri         = $uri
            Method      = 'Post'
            Body        = $body
            ContentType = 'application/json'
        }
        if ($SkipCertificateCheck) {
            $irmParams['SkipCertificateCheck'] = $true
        }

        try {
            $response = Invoke-RestMethod @irmParams
        }
        catch {
            [string]$detail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            throw "Ошибка LDAP-аутентификации в Vault ($uri): $detail"
        }
        finally {
            $password = $null
        }

        [string]$token = $response.auth.client_token
        if ([string]::IsNullOrEmpty($token)) {
            throw 'Vault не вернул client_token в ответе.'
        }

        $env:VAULT_ADDR = $VaultAddr
        $env:VAULT_TOKEN = $token

        [string]$successMessage = "VAULT_TOKEN установлен. Policies: {0}; lease_duration: {1}s" -f `
            ($response.auth.policies -join ', '), $response.auth.lease_duration
        Write-Information -MessageData $successMessage -InformationAction "Continue"
    }

    end {}
}
