!ifndef SOURCE_EXE
  !error "SOURCE_EXE must point to the release omnidesk-desktop.exe"
!endif

!ifndef OUTPUT_EXE
  !define OUTPUT_EXE "KMJ-OmniDesk-unsigned-setup.exe"
!endif

Unicode true
RequestExecutionLevel admin
SetCompressor /SOLID zlib

Name "KMJ OmniDesk"
OutFile "${OUTPUT_EXE}"
InstallDir "$PROGRAMFILES64\KMJ OmniDesk"
InstallDirRegKey HKLM "Software\KMJ TECHNO\OmniDesk" "InstallDir"
ShowInstDetails nevershow
ShowUninstDetails nevershow
SilentInstall silent
SilentUnInstall silent

Section "KMJ OmniDesk" SEC_MAIN
  SetOutPath "$INSTDIR"
  File /oname=omnidesk-desktop.exe "${SOURCE_EXE}"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  WriteRegStr HKLM "Software\KMJ TECHNO\OmniDesk" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KMJOmniDesk" "DisplayName" "KMJ OmniDesk"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KMJOmniDesk" "Publisher" "KMJ TECHNO"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KMJOmniDesk" "DisplayVersion" "0.0.1"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KMJOmniDesk" "UninstallString" '"$INSTDIR\Uninstall.exe"'
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\omnidesk-desktop.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "Software\KMJ TECHNO\OmniDesk"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KMJOmniDesk"
SectionEnd
