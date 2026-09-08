# 배포 zip에 넣을 바로가기(.lnk)를 만든다.
#
# 배치 파일은 아이콘을 가질 수 없다 - Windows가 .bat 에 항상 같은 톱니바퀴 아이콘을
# 씌운다. 그래서 사용자가 실제로 누를 대상은 아이콘을 지정할 수 있는 바로가기로 두고,
# 그 바로가기가 scan.bat 을 실행하게 한다.
#
# 바로가기는 대상의 절대 경로를 담지만 상대 경로도 함께 저장한다(SetRelativePath).
# 사용자가 압축을 어디에 풀든 만들 때의 절대 경로는 맞지 않으므로, Windows 는 이 상대
# 경로로 대상을 다시 찾는다. 따라서 바로가기와 scan.bat, secrethound.exe 는 반드시
# 같은 폴더에 나란히 있어야 한다.
#
# WScript.Shell 을 쓰지 않는 이유:
#   그 COM 개체는 문자열을 시스템 ANSI 코드페이지로 변환한다. 그래서 코드페이지가
#   한글을 표현하지 못하는 환경(영문 Windows·GitHub Actions 러너 등)에서는
#   '시크릿 검사하기.lnk' 가 '??? ????.lnk' 가 되어 저장 자체가 실패하고, 설명(툴팁)은
#   실패 없이 조용히 '???' 로 망가진다. IShellLinkW/IPersistFile 은 UTF-16으로
#   주고받으므로 시스템 코드페이지와 무관하게 동작한다.

param(
    # scan.bat 과 secrethound.exe 가 들어있는 폴더
    [Parameter(Mandatory = $true)][string]$Folder,
    [string]$Name = '시크릿 검사하기.lnk'
)

$ErrorActionPreference = 'Stop'

if (-not ('SecretHound.Shortcut' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SecretHound
{
    [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
    internal class ShellLinkObject { }

    [ComImport, Guid("000214F9-0000-0000-C000-000000000046"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IShellLinkW
    {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile,
                     int cch, IntPtr pfd, int fFlags);
        void GetIDList(out IntPtr ppidl);
        void SetIDList(IntPtr pidl);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName, int cch);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir, int cch);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs, int cch);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
        void GetHotkey(out short pwHotkey);
        void SetHotkey(short wHotkey);
        void GetShowCmd(out int piShowCmd);
        void SetShowCmd(int iShowCmd);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath,
                             int cch, out int piIcon);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, int dwReserved);
        void Resolve(IntPtr hwnd, int fFlags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
    }

    [ComImport, Guid("0000010b-0000-0000-C000-000000000046"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IPersistFile
    {
        void GetClassID(out Guid pClassID);
        [PreserveSig] int IsDirty();
        void Load([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, int dwMode);
        void Save([MarshalAs(UnmanagedType.LPWStr)] string pszFileName,
                  [MarshalAs(UnmanagedType.Bool)] bool fRemember);
        void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string pszFileName);
        void GetCurFile([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder ppszFileName);
    }

    public static class Shortcut
    {
        public static void Create(string linkPath, string target, string workingDirectory,
                                  string iconPath, int iconIndex, string description)
        {
            var link = (IShellLinkW)new ShellLinkObject();

            link.SetPath(target);
            if (!string.IsNullOrEmpty(workingDirectory)) { link.SetWorkingDirectory(workingDirectory); }
            if (!string.IsNullOrEmpty(iconPath)) { link.SetIconLocation(iconPath, iconIndex); }
            if (!string.IsNullOrEmpty(description)) { link.SetDescription(description); }

            // 압축을 푼 위치가 달라도 대상을 다시 찾을 수 있도록, 바로가기 자신을
            // 기준으로 한 상대 경로를 함께 저장한다.
            link.SetRelativePath(linkPath, 0);

            ((IPersistFile)link).Save(linkPath, true);
        }
    }
}
'@
}

$folder = (Resolve-Path -LiteralPath $Folder).Path
$bat = Join-Path $folder 'scan.bat'
$exe = Join-Path $folder 'secrethound.exe'

foreach ($required in @($bat, $exe)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "필요한 파일이 없습니다: $required"
    }
}

$linkPath = Join-Path $folder $Name

# 아이콘은 exe 안에 박아둔 것을 그대로 쓴다 (assets/icon.ico → resource .syso).
[SecretHound.Shortcut]::Create(
    $linkPath, $bat, $folder, $exe, 0,
    'secrethound: 폴더를 골라 유출된 API 키·시크릿을 검사합니다')

if (-not (Test-Path -LiteralPath $linkPath)) {
    throw "바로가기를 만들지 못했습니다: $linkPath"
}

Write-Output "created: $linkPath"
