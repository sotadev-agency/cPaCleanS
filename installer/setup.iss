; Inno Setup Script — cPacleanS v3.0.2
; Editor: Sota Studio Web | https://sotastudioweb.com
; Descargar Inno Setup 6: https://jrsoftware.org/isinfo.php

#define MyAppName        "cPacleanS"
#define MyAppVersion     "3.0.2"
#define MyAppPublisher   "Sota Studio Web"
#define MyAppURL         "https://github.com/sotadev-agency/cPaCleanS"
#define MyAppSupportURL  "https://github.com/sotadev-agency/cPaCleanS/issues"
#define MyAppExeName     "cPacleanS.exe"
#define MyAppDescription "Malware Cleaner para backups cPanel"

[Setup]
; GUID unico del instalador — NO cambiar entre versiones (identifica el producto para updates)
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} v{#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppSupportURL}
AppUpdatesURL={#MyAppURL}/releases
AppCopyright=Copyright (c) 2024-2026 Sota Studio Web

; Rutas de instalacion
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes

; Archivos de la instalacion
LicenseFile=..\LICENSE.txt
OutputDir=..\dist\installer
OutputBaseFilename=cPacleanS_Setup_v{#MyAppVersion}
SetupIconFile=..\assets\icon.ico

; Compresion maxima
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern

; Privilegios y arquitectura
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Desinstalador
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} v{#MyAppVersion}

; Metadata de version para Windows — ayuda al reconocimiento por antivirus y SmartScreen
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppDescription}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}.0
VersionInfoCopyright=Copyright (c) 2024-2026 Sota Studio Web

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Crear icono en el Escritorio"; GroupDescription: "Accesos directos:"; Flags: unchecked

[Files]
Source: "..\dist\cPacleanS.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE.txt";        DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";          DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#MyAppName}";              Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Desinstalar {#MyAppName}";  Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";        Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Ejecutar {#MyAppName} ahora"; Flags: nowait postinstall skipifsilent

[Code]
// Mostrar pagina de informacion adicional durante la instalacion
procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel2.Caption :=
    'Este asistente instalara ' + ExpandConstant('{#MyAppName}') + ' v' +
    ExpandConstant('{#MyAppVersion}') + ' en su equipo.' + #13#10 + #13#10 +
    'AVISO DE SEGURIDAD: Si su antivirus detecta este instalador como sospechoso, ' +
    'es un falso positivo. cPacleanS es una herramienta de seguridad legitima ' +
    'con codigo fuente publicado en GitHub.' + #13#10 + #13#10 +
    'Haga clic en Siguiente para continuar.';
end;
