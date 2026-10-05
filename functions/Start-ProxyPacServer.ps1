function Start-ProxyPacServer {
    <#
    .SYNOPSIS
        Запускает HTTP-сервер, отдающий PAC-файл (Proxy Auto-Config) для настройки прокси в Windows.

    .DESCRIPTION
        Start-ProxyPacServer формирует PAC-файл для указанного прокси-сервера и списка доменов,
        а затем запускает отдельный, полностью отсоединённый от вызывающего процесс pwsh, который
        поднимает HTTP-сервер на 127.0.0.1 и отдаёт этот PAC-файл по указанному порту.

        Сама функция возвращает управление практически сразу после запуска — реальная работа
        (HTTP-listener) выполняется в независимом фоновом процессе, который продолжает работать
        вне зависимости от того, кто и как её вызвал. Благодаря этому функцию можно, например,
        вызывать из задания в Планировщике заданий Windows, не оставляя само задание висеть
        в состоянии "Выполняется" на всё время работы сервера.

        Итоговый список проксируемых доменов собирается из двух источников и объединяется:
          - необязательная глобальная переменная $global:ProxyPacServerDomains — удобно задать
            её в своём профиле PowerShell ($PROFILE), чтобы иметь единый список доменов
            "по умолчанию" для всех вызовов функции в сессии, не передавая его каждый раз явно;
          - параметр -ProxiedDomains — список доменов для конкретного вызова.
        Любой из источников может отсутствовать или быть пустым (в т.ч. передан явно как пустой
        массив) — сервер всё равно запустится и будет работать, просто PAC-файл не будет
        назначать прокси ни для одного домена (FindProxyForURL всегда будет возвращать DIRECT).

    .PARAMETER ProxyServer
        Адрес и порт целевого прокси-сервера в формате "host:port". Указывается в PAC-файле
        как "PROXY host:port" для всех доменов из итогового списка.

    .PARAMETER Port
        Порт, на котором локальный HTTP-сервер (127.0.0.1) будет отдавать PAC-файл.
        По умолчанию — 8923.

    .PARAMETER ProxiedDomains
        Список доменов (с учётом поддоменов), для которых в PAC-файле нужно назначить прокси.
        Объединяется с доменами из $global:ProxyPacServerDomains, если та задана. Можно не
        указывать вовсе или передать пустой массив — тогда используются только домены
        из глобальной переменной (если она задана).

    .PARAMETER LogPath
        Путь к файлу лога. Если не указан, используется
        "$env:LOCALAPPDATA\ProxyPacServer\server.log". Недостающие родительские каталоги
        создаются автоматически.

    .PARAMETER RegisterScheduledTask
        Вместо немедленного запуска сервера зарегистрировать (или перезаписать, если уже
        существует) назначенное задание "Start proxy PAC server" в Планировщике заданий Windows
        с триггером "при входе в систему" текущего пользователя. При каждом входе задание само
        вызовет Start-ProxyPacServer с теми же параметрами, что были переданы при регистрации.

    .PARAMETER SetWindowsProxy
        Настроить общесистемный прокси текущего пользователя (Параметры Windows → Сеть и
        Интернет → Прокси-сервер → "Использовать сценарий настройки") на адрес этого PAC-сервера
        ("http://127.0.0.1:<Port>/"). Применяется сразу (через AutoConfigURL в HKCU и уведомление
        WinINet), без выхода из системы и без прав администратора. Если также указан
        -RegisterScheduledTask, эта настройка будет переприменяться при каждом входе в систему.

    .EXAMPLE
        Start-ProxyPacServer -ProxyServer "proxy.contoso.com:8080" -ProxiedDomains "anthropic.com", "claude.ai"

        Запускает PAC-сервер на порту по умолчанию (8923), который назначает прокси
        "proxy.contoso.com:8080" для доменов anthropic.com и claude.ai (с поддоменами).

    .EXAMPLE
        # В профиле PowerShell ($PROFILE):
        $global:ProxyPacServerDomains = @("anthropic.com", "claude.ai", "claude.com")

        # Далее в любом вызове достаточно указать только прокси:
        Start-ProxyPacServer -ProxyServer "proxy.contoso.com:8080"

        Список доменов "по умолчанию" задаётся через глобальную переменную в профиле, чтобы
        не передавать -ProxiedDomains вручную при каждом вызове. При запуске функции этот
        список автоматически объединяется с -ProxiedDomains, если он тоже передан.

    .EXAMPLE
        Start-ProxyPacServer -ProxyServer "proxy.contoso.com:8080" -ProxiedDomains "anthropic.com" -RegisterScheduledTask

        Регистрирует (перезаписывая, если уже существует) задание "Start proxy PAC server"
        в Планировщике заданий Windows с триггером "при входе в систему". Сервер при этом
        не запускается — он поднимется при следующем входе в систему.

    .EXAMPLE
        Start-ProxyPacServer -ProxyServer "proxy.contoso.com:8080" -Port 8923 -SetWindowsProxy

        Запускает сервер немедленно и сразу же настраивает общесистемный прокси Windows
        на "http://127.0.0.1:8923/" — эквивалент ручного включения "Использовать сценарий
        настройки" в Параметры → Сеть и Интернет → Прокси-сервер.

    .NOTES
        Предполагается запуск через задание в Планировщике заданий Windows: сама функция
        быстро завершается, а HTTP-сервер продолжает работать в независимом фоновом процессе,
        поэтому задание не будет висеть в состоянии "Выполняется".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrWhiteSpace()]
        [string]$ProxyServer,

        [Parameter()]
        [int]$Port = 8923,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$ProxiedDomains,

        [Parameter()]
        [ValidateNotNullOrWhiteSpace()]
        [string]$LogPath = "$env:LOCALAPPDATA\ProxyPacServer\server.log",

        [Parameter()]
        [switch]$RegisterScheduledTask,

        [Parameter()]
        [switch]$SetWindowsProxy
    )

    $ErrorActionPreference = "Stop"

    New-Item -ItemType Directory -Path (Split-Path -Path $LogPath -Parent) -Force | Out-Null

    # Получение общего списка доменов для проксирования.
    # @(...) оборачивает каждый источник в массив, а Where-Object отфильтровывает $null,
    # чтобы при отсутствии global:ProxyPacServerDomains и/или ProxiedDomains получался
    # настоящий пустой массив @(), а не массив с одним пустым/null-элементом.
    [string[]]$AllProxiedDomains = @(@($global:ProxyPacServerDomains) + @($ProxiedDomains) | Where-Object { $_ })

    # Дописывает строку с меткой времени в лог-файл.
    function Write-Log([string]$Message) {
        [string]$line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    }

    # Безопасно оборачивает строку в одинарные кавычки для подстановки в текст генерируемого скрипта.
    function ConvertTo-PSLiteral([string]$Value) {
        "'{0}'" -f ($Value -replace "'", "''")
    }

    # Строит base64-команду для -EncodedCommand: $Prelude (подготовительный код) + вызов $Call
    # со сплатом параметров из $Arguments. Параметры проходят через JSON, а не через ручную сборку
    # литералов под каждый тип (строка/массив/число) отдельно для каждого места вызова.
    function New-EncodedInvocation {
        param([string]$Prelude, [string]$Call, [hashtable]$Arguments)

        [string]$argsJsonLiteral = ConvertTo-PSLiteral -Value ($Arguments | ConvertTo-Json -Compress -Depth 3)
        [string]$script = @"
$Prelude
[hashtable]`$CallArgs = ConvertFrom-Json -InputObject $argsJsonLiteral -AsHashtable
$Call @CallArgs
"@
        [byte[]]$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
        [Convert]::ToBase64String($bytes)
    }

    [string]$pwshPath = (Get-Process -Id $PID).Path
    [hashtable]$CommonArgs = @{
        ProxyServer    = $ProxyServer
        Port           = $Port
        ProxiedDomains = $AllProxiedDomains
        LogPath        = $LogPath
    }

    if ($SetWindowsProxy) {
        # Записывает AutoConfigURL в HKCU (не требует прав администратора) и уведомляет
        # WinINet через InternetSetOption, чтобы изменение применилось сразу, без выхода
        # из системы — именно так Windows сама записывает адрес сценария настройки в
        # Параметры → Сеть и Интернет → Прокси-сервер → "Использовать сценарий настройки".
        [string]$autoConfigUrl = "http://127.0.0.1:$Port/"
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoConfigURL" -Value $autoConfigUrl -Type String -Force

            if (-not ("Win32.WinInet" -as [type])) {
                Add-Type -Namespace Win32 -Name WinInet -MemberDefinition @'
[DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
            }
            [void][Win32.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) # INTERNET_OPTION_SETTINGS_CHANGED
            [void][Win32.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) # INTERNET_OPTION_REFRESH

            Write-Log "Настроен общесистемный прокси (AutoConfigURL = $autoConfigUrl)"
        }
        catch {
            Write-Log "Не удалось настроить общесистемный прокси: $_"
            throw
        }
    }

    if ($RegisterScheduledTask) {
        # Регистрация/перезапись назначенного задания вместо немедленного запуска сервера:
        # само задание при срабатывании триггера вызовет Start-ProxyPacServer с этими же
        # параметрами (дот-сорсинг файла этой функции по пути, т.к. он не меняется между
        # перезапусками, в отличие от отсоединённого процесса воркера).
        [string]$taskName = "Start proxy PAC server"
        [string]$currentUser = "$env:USERDOMAIN\$env:USERNAME"

        [hashtable]$TaskArgs = $CommonArgs.Clone()
        if ($SetWindowsProxy) { $TaskArgs.SetWindowsProxy = $true }

        [string]$taskEncodedCommand = New-EncodedInvocation -Prelude ". $(ConvertTo-PSLiteral -Value $PSCommandPath)" -Call "Start-ProxyPacServer" -Arguments $TaskArgs
        [string]$taskArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $taskEncodedCommand"

        [hashtable]$TaskParams = @{
            TaskName  = $taskName
            Action    = New-ScheduledTaskAction -Execute $pwshPath -Argument $taskArguments
            Trigger   = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
            Principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
            Settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            Force     = $true
        }

        try {
            Register-ScheduledTask @TaskParams | Out-Null
            Write-Log "Зарегистрировано задание Планировщика '$taskName'"
        }
        catch {
            Write-Log "Не удалось зарегистрировать задание Планировщика: $_"
            throw
        }

        return
    }

    # Само тело Start-ProxyPacServerWorker подставляется как текст, чтобы отсоединённому
    # процессу не нужно было ничего импортировать — он самодостаточен.
    [string]$workerDefinition = (Get-Command -Name "Start-ProxyPacServerWorker").ScriptBlock.ToString()
    [string]$encodedCommand = New-EncodedInvocation -Prelude "function Start-ProxyPacServerWorker {`n$workerDefinition`n}" -Call "Start-ProxyPacServerWorker" -Arguments $CommonArgs

    [hashtable]$StartProcessParams = @{
        FilePath     = $pwshPath
        ArgumentList = @(
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-EncodedCommand", $encodedCommand
        )
        WindowStyle  = "Hidden"
        PassThru     = $true
    }

    try {
        $workerProcess = Start-Process @StartProcessParams
        Write-Log "Запущен фоновый процесс PAC-сервера, PID: $($workerProcess.Id)"
    }
    catch {
        Write-Log "Не удалось запустить фоновый процесс PAC-сервера: $_"
        throw
    }
}

function Start-ProxyPacServerWorker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProxyServer,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$ProxiedDomains,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $ErrorActionPreference = "Stop"

    # Дописывает строку с меткой времени в лог-файл.
    function Write-ErrorLog([string]$Message) {
        [string]$line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    }

    # Генерирует содержимое PAC-файла (JavaScript) для заданного прокси и списка доменов.
    function Get-PacContent {
        param([string]$Proxy, [string[]]$Domains)

        [string]$domainsJson = ConvertTo-Json -InputObject @($Domains) -Compress

        @"
var PROXY = "PROXY $Proxy";
var DIRECT = "DIRECT";
var PROXIED_DOMAINS = $domainsJson;

function FindProxyForURL(url, host) {
    host = host.toLowerCase();

    for (var i = 0; i < PROXIED_DOMAINS.length; i++) {
        var domain = PROXIED_DOMAINS[i];
        if (host === domain || dnsDomainIs(host, "." + domain)) {
            return PROXY;
        }
    }

    return DIRECT;
}
"@
    }

    [string]$pacContent = Get-PacContent -Proxy $ProxyServer -Domains $ProxiedDomains
    [byte[]]$bytes = [System.Text.Encoding]::UTF8.GetBytes($pacContent)

    $listener = $null
    try {
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:$Port/")
        $listener.Start()

        while ($listener.IsListening) {
            try {
                $context = $listener.GetContext()
                $context.Response.ContentType = "application/x-ns-proxy-autoconfig"
                $context.Response.ContentLength64 = $bytes.Length
                $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $context.Response.OutputStream.Close()
            }
            catch {
                Write-ErrorLog -Message "Ошибка обработки запроса: $_"
            }
        }
    }
    catch {
        Write-ErrorLog -Message "Сервер остановлен из-за ошибки: $_"
    }
    finally {
        if ($listener) {
            $listener.Stop()
            $listener.Close()
        }
    }
}
