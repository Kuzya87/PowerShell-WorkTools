function Set-WorkVaultTokenEnv {
    <#
    .SYNOPSIS
        Получает Vault token через LDAP auth-метод и записывает его в $env:VAULT_TOKEN.
    .DESCRIPTION
        Выполняет аутентификацию в HashiCorp Vault по auth-методу LDAP, используя переданные
        учётные данные (например, доменную учётную запись AD). Из имени пользователя удаляется
        суффикс вида "@domain", если он присутствует. При успешном ответе от Vault функция
        записывает адрес сервера и полученный токен в переменные окружения $env:VAULT_ADDR и
        $env:VAULT_TOKEN, а также выводит информационное сообщение со списком policies и
        временем жизни токена (lease_duration). Пароль из учётных данных удаляется из памяти
        после выполнения запроса.
    .PARAMETER VaultAddr
        Адрес Vault-сервера, включая схему (http/https), например 'https://vault.contoso.test'.
        Обязательный параметр.
    .PARAMETER Credential
        Учётные данные (PSCredential) для LDAP-аутентификации в Vault. Обязательный параметр.
        Если имя пользователя указано в формате UPN (user@domain), суффикс домена отбрасывается.
    .PARAMETER AuthMount
        Путь монтирования auth-метода LDAP в Vault. По умолчанию 'ldap'.
    .PARAMETER SkipCertificateCheck
        Отключает проверку TLS-сертификата Vault-сервера при выполнении запроса.
        Использовать только для тестовых сред с самоподписанными сертификатами.
    .EXAMPLE
        Set-WorkVaultTokenEnv -VaultAddr 'https://vault.contoso.test'

        Запрашивает учётные данные и выполняет аутентификацию с настройками auth-метода по умолчанию.
    .EXAMPLE
        Set-WorkVaultTokenEnv -VaultAddr 'https://vault.contoso.test' -Credential $cred

        Выполняет аутентификацию с явно переданными учётными данными.
    .EXAMPLE
        Set-WorkVaultTokenEnv -VaultAddr 'https://vault.contoso.test' -Credential $cred -AuthMount 'ldap-corp' -SkipCertificateCheck

        Использует нестандартный путь монтирования auth-метода и отключает проверку сертификата.
    .INPUTS
        Нет. Функция не принимает данные из конвейера.
    .OUTPUTS
        Нет. Функция не возвращает объекты в конвейер, только устанавливает переменные окружения
        и выводит информационное сообщение через Write-Information.
    .NOTES
        При ошибке аутентификации или отсутствии client_token в ответе Vault функция выбрасывает
        исключение (terminating error).
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
