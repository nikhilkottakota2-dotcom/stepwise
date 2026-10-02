$ErrorActionPreference = 'Stop'

$env:SMTP_HOST = 'smtp.gmail.com'
$env:SMTP_PORT = '587'
$env:SMTP_USER = 'kottakotanikhil75@gmail.com'
$env:SMTP_FROM = "Stepwise <$($env:SMTP_USER)>"
$env:APP_BASE_URL = 'http://127.0.0.1:8000'

if (-not $env:SMTP_PASSWORD) {
    $securePassword = Read-Host 'Enter the Gmail app password for Stepwise' -AsSecureString
    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    try {
        $env:SMTP_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer).Replace(' ', '')
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }
}

python (Join-Path $PSScriptRoot 'server.py')
