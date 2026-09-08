# 배포 zip에 넣을 바로가기(.lnk)를 만든다.
#
# 배치 파일은 아이콘을 가질 수 없다 - Windows가 .bat 에 항상 같은 톱니바퀴 아이콘을
# 씌운다. 그래서 사용자가 실제로 누를 대상은 아이콘을 지정할 수 있는 바로가기로 두고,
# 그 바로가기가 scan.bat 을 실행하게 한다.
#
# 바로가기는 대상의 절대 경로를 담지만, IShellLink 는 바로가기 자신을 기준으로 한
# 상대 경로도 함께 저장한다. 사용자가 압축을 어디에 풀든 만들 때의 절대 경로는 맞지
# 않으므로, Windows 는 이 상대 경로로 대상을 다시 찾는다. 따라서 바로가기와
# scan.bat, secrethound.exe 는 반드시 같은 폴더에 나란히 있어야 한다.

param(
    # scan.bat 과 secrethound.exe 가 들어있는 폴더
    [Parameter(Mandatory = $true)][string]$Folder,
    [string]$Name = '시크릿 검사하기.lnk'
)

$ErrorActionPreference = 'Stop'

$folder = (Resolve-Path -LiteralPath $Folder).Path
$bat = Join-Path $folder 'scan.bat'
$exe = Join-Path $folder 'secrethound.exe'

foreach ($required in @($bat, $exe)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "필요한 파일이 없습니다: $required"
    }
}

$linkPath = Join-Path $folder $Name

$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($linkPath)
$link.TargetPath = $bat
$link.WorkingDirectory = $folder
# 아이콘은 exe 안에 박아둔 것을 그대로 쓴다 (assets/icon.ico → resource .syso).
$link.IconLocation = "$exe,0"
$link.Description = 'secrethound: 폴더를 골라 유출된 API 키·시크릿을 검사합니다'
$link.Save()

Write-Output "created: $linkPath"
