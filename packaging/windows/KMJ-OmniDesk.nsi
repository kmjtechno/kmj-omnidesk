!ifndef SOURCE_EXE
  !error "SOURCE_EXE must point to the release omnidesk-desktop.exe"
!endif

!ifndef OUTPUT_EXE
  !define OUTPUT_EXE "KMJ-OmniDesk-unsigned-setup.exe"
!endif

!ifndef APP_VERSION
  !define APP_VERSION "0.0.1"
!endif

!include "MUI2.nsh"

Unicode true
RequestExecutionLevel admin
SetCompressor /SOLID zlib

Name "KMJ OmniDesk"
OutFile "${OUTPUT_EXE}"
InstallDir "$PROGRAMFILES64\KMJ OmniDesk"
InstallDirRegKey HKLM "Software\KMJ TECHNO\OmniDesk" "InstallDir"

; Normal customer installs should show a usable native Windows wizard.
; The existing CI and managed-deployment /S option remains fully silent.
SilentInstall normal
SilentUnInstall normal
ShowInstDetails show
ShowUninstDetails show
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "KMJ OmniDesk Setup"
!define MUI_WELCOMEPAGE_TEXT "Install KMJ OmniDesk remote access on this device. Internet connectivity and commercial activation require separately verified services."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "KMJ OmniDesk" SEC_MAIN
  SetShellVarContext all
  SetOutPath "$INSTDIR"
  File /oname=omnidesk-desktop.exe "${SOURCE_EXE}"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateShortCut "$SMPROGRAMS\KMJ OmniDesk.lnk" "$INSTDIR\omnidesk-desktop.exe"

  WriteRegStr HKLM "Software\KMJ TECHNO\OmniDesk" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KMJOmniDesk" "DisplayName" "KMJ OmniDesk"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KMJOmniDesk" "Publisher" "KMJ TECHNO"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KMJOmniDesk" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KMJOmniDesk" "UninstallString" '"$INSTDIR\Uninstall.exe"'
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  Delete "$SMPROGRAMS\KMJ OmniDesk.lnk"
  Delete "$INSTDIR\omnidesk-desktop.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "Software\KMJ TECHNO\OmniDesk"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\KMJOmniDesk"
SectionEnd
