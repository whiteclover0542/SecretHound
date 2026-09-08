# 폴더를 배포용 zip으로 묶는다.
#
# 그냥 압축하면 안 되는 이유: .NET(Compress-Archive 포함)은 파일 이름을 UTF-8
# 바이트로 쓰면서도 zip 헤더의 "이름이 UTF-8"이라는 표시(general purpose bit 11)를
# 켜지 않는다. 그러면 그 표시를 보고 인코딩을 정하는 압축 해제 도구는 이름을 시스템
# 코드페이지(한국어 Windows면 949)로 읽어, '시크릿 검사하기.lnk' 같은 이름이 깨진다.
# Windows 탐색기는 UTF-8을 스스로 알아채지만 다른 도구까지 그러리라 기대할 수 없다.
#
# 그래서 압축한 뒤 모든 항목의 bit 11을 직접 켠다. 이름은 이미 UTF-8 바이트로
# 들어가 있으므로, 표시만 바로잡으면 규격에 맞는 zip이 된다.

param(
    [Parameter(Mandatory = $true)][string]$Folder,
    [Parameter(Mandatory = $true)][string]$Destination
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$folder = (Resolve-Path -LiteralPath $Folder).Path

# .NET API는 상대 경로를 PowerShell의 현재 위치(Get-Location)가 아니라 프로세스의
# 작업 디렉토리 기준으로 푼다. 이 둘은 다를 수 있고, 특히 CI에서 갈린다. 상대 경로를
# 그대로 넘기면 엉뚱한 위치를 찾다가 "Could not find a part of the path"로 죽는다.
if (-not [System.IO.Path]::IsPathRooted($Destination)) {
    $Destination = Join-Path (Get-Location).Path $Destination
}
$Destination = [System.IO.Path]::GetFullPath($Destination)

$parent = Split-Path -Parent $Destination
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

if (Test-Path -LiteralPath $Destination) {
    Remove-Item -LiteralPath $Destination
}

[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $folder, $Destination,
    [System.IO.Compression.CompressionLevel]::Optimal,
    $false,
    [System.Text.Encoding]::UTF8)

# --- UTF-8 표시 켜기 ---
#
# 압축 데이터 안에도 헤더와 같은 바이트열이 우연히 나올 수 있으므로, 시그니처를
# 훑어 찾지 않고 중앙 디렉토리를 규격대로 따라간다.
$bytes = [System.IO.File]::ReadAllBytes($Destination)

function Get-UInt16([byte[]]$b, [int]$at) { [BitConverter]::ToUInt16($b, $at) }
function Get-UInt32([byte[]]$b, [int]$at) { [BitConverter]::ToUInt32($b, $at) }

# End of Central Directory 레코드를 뒤에서부터 찾는다 (주석이 붙어 있을 수 있다).
$eocd = -1
for ($i = $bytes.Length - 22; $i -ge 0; $i--) {
    if ($bytes[$i] -eq 0x50 -and $bytes[$i + 1] -eq 0x4B -and
        $bytes[$i + 2] -eq 0x05 -and $bytes[$i + 3] -eq 0x06) {
        $eocd = $i
        break
    }
}
if ($eocd -lt 0) { throw 'zip의 End of Central Directory를 찾지 못했습니다' }

$entryCount = Get-UInt16 $bytes ($eocd + 10)
$pos = [int](Get-UInt32 $bytes ($eocd + 16))

$utf8Flag = 0x0800
for ($n = 0; $n -lt $entryCount; $n++) {
    if ($bytes[$pos] -ne 0x50 -or $bytes[$pos + 1] -ne 0x4B -or
        $bytes[$pos + 2] -ne 0x01 -or $bytes[$pos + 3] -ne 0x02) {
        throw "중앙 디렉토리 항목 $n 의 시그니처가 올바르지 않습니다"
    }

    # 중앙 디렉토리 쪽 플래그
    $flag = Get-UInt16 $bytes ($pos + 8)
    [void][BitConverter]::GetBytes([uint16]($flag -bor $utf8Flag)).CopyTo($bytes, $pos + 8)

    # 같은 항목의 로컬 헤더 쪽 플래그
    $localAt = [int](Get-UInt32 $bytes ($pos + 42))
    if ($bytes[$localAt] -ne 0x50 -or $bytes[$localAt + 1] -ne 0x4B -or
        $bytes[$localAt + 2] -ne 0x03 -or $bytes[$localAt + 3] -ne 0x04) {
        throw "항목 $n 의 로컬 헤더를 찾지 못했습니다"
    }
    $localFlag = Get-UInt16 $bytes ($localAt + 6)
    [void][BitConverter]::GetBytes([uint16]($localFlag -bor $utf8Flag)).CopyTo($bytes, $localAt + 6)

    $nameLen = Get-UInt16 $bytes ($pos + 28)
    $extraLen = Get-UInt16 $bytes ($pos + 30)
    $commentLen = Get-UInt16 $bytes ($pos + 32)
    $pos += 46 + $nameLen + $extraLen + $commentLen
}

[System.IO.File]::WriteAllBytes($Destination, $bytes)
Write-Output "created: $Destination ($entryCount files)"
