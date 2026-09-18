; ---------------------------------------------------------------------------
;  Smart Windows Cleaner — Version-Agnostic Bootstrapper Setup
;
;  Small (~2-3 MB class) downloader/installer. Reads the production release
;  manifests (latest.yml + portable.yml), lets the user choose between Full
;  Installation and Portable Version, downloads exactly one payload,
;  cryptographically verifies it (SHA-512 from manifest), and launches or
;  extracts it.
;
;  Framework: pure Inno Setup 6.2+ built-ins — TDownloadWizardPage,
;  TExtractionWizardPage, PowerShell Get-FileHash.
;  Zero third-party plugins, no curl driving, no timers.
;
;  Trust & Verification Rules:
;   - Payload filenames come strictly from release manifests.
;   - Nothing executes or extracts before its SHA-512 verifies against
;     the manifest. Mismatch => delete + abort (fail-closed).
;   - The offline cache is a mirror, not a trust root: cached payloads are
;     re-verified against their cached manifest copy on every use.
;
;  Build with:  ISCC.exe installer\bootstrapper.iss
; ---------------------------------------------------------------------------

#if Ver < 0x06020000
  #error "bootstrapper.iss requires Inno Setup 6.2 or newer (native download/extraction pages)"
#endif

#define MyAppName "Smart Windows Cleaner"
#define MyAppVersion "1.0.2"
#define MyAppPublisher "Abdelrahman Aboelsaad"
#define MyAppURL "https://github.com/Aboelsaad77/smart-windows-cleaner"
#define MyAppExeName "SmartCleaner.exe"
; Single feed constant pointing to GitHub Releases latest download
#define FeedBaseUrl "https://github.com/Aboelsaad77/smart-windows-cleaner/releases/latest/download/"
#ifndef OutputDir
  #define OutputDir "..\desktop\dist-release"
#endif

[Setup]
; Bootstrapper identity only — nothing is registered (Uninstallable=no).
; Distinct from the installed application NSIS GUID.
AppId={{4E8A9B5D-C7A2-1D2C-A3F6-5E7B9A04B2E1}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} Setup {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
CreateAppDir=no
Uninstallable=no
; Starting Setup never requires admin. Full mode delegates elevation to the
; NSIS payload; Portable never elevates.
PrivilegesRequired=lowest
; Payloads are x64-only; refuse x86/arm outright.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Native ZIP extraction for Portable mode
ArchiveExtraction=full
OutputDir={#OutputDir}
; UNVERSIONED by design: stable setup filename across releases.
OutputBaseFilename=SmartCleaner-Setup
SetupIconFile=app.ico
LicenseFile=license.txt
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup
VersionInfoProductName={#MyAppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
DisableWelcomePage=no
CloseApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "arabic"; MessagesFile: "compiler:Languages\Arabic.isl"

[Messages]
english.WelcomeLabel2=This Setup downloads the latest {#MyAppName} — Full Installation or Portable Version, your choice — verifies it, and installs it.%n%nClick Next to continue.
arabic.WelcomeLabel2=يقوم هذا المعالج بتنزيل أحدث إصدار من {#MyAppName} — تثبيت كامل أو نسخة محمولة حسب اختيارك — ثم يتحقق منه ويثبّته.%n%nانقر التالي للمتابعة.

[CustomMessages]
english.ModeCaption=Choose install type
english.ModeDesc=How should Setup install {#MyAppName}?
english.ModeSub=Pick one option, then click Next.
english.ModeFull=Full Installation (recommended)
english.ModePort=Portable Version (no install)
english.ModeOnline=Release feed reachable. Latest: Full %1 · Portable %2.
english.ModeCacheOnly=Offline — verified on-disk cache will be used: %1 (%2).
english.ModeNoSource=No connection and no verified cache — cannot continue. Reconnect and restart Setup.
english.DirCaption=Choose portable folder
english.DirDesc=Where should the portable copy be extracted?
english.DirSub=Pick an empty folder you own (Documents, USB stick).
english.DirPrompt=Portable folder:
english.DlCaption=Downloading
english.DlDesc=Downloading the install package…
english.ExCaption=Extracting
english.ExDesc=Extracting the portable copy…
arabic.ModeCaption=اختر نوع التثبيت
arabic.ModeDesc=كيف تريد أن يثبّت المعالج {#MyAppName}؟
arabic.ModeSub=اختر خيارًا واحدًا ثم انقر التالي.
arabic.ModeFull=تثبيت كامل (مُوصى به)
arabic.ModePort=نسخة محمولة (بدون تثبيت)
arabic.ModeOnline=مصدر الإصدارات متاح. الأحدث: %1 (كامل) · %2 (محمول).
arabic.ModeCacheOnly=لا يوجد اتصال — سيُستخدم مخزون موثوق على القرص: %1 (%2).
arabic.ModeNoSource=لا يوجد اتصال ولا نسخة محفوظة موثوقة — تعذّر المتابعة. أعد الاتصال ثم أعد تشغيل المعالج.
arabic.DirCaption=اختر مجلد النسخة المحمولة
arabic.DirDesc=أين تُستخرج النسخة المحمولة؟
arabic.DirSub=اختر مجلدًا فارغًا تملكه (المستندات، ذاكرة USB).
arabic.DirPrompt=مجلد النسخة:
arabic.DlCaption=جارٍ التنزيل
arabic.DlDesc=جارٍ تنزيل حزمة التثبيت…
arabic.ExCaption=جارٍ الاستخراج
arabic.ExDesc=جارٍ استخراج النسخة المحمولة…

[Code]
const
  LatestManifest = 'latest.yml';
  PortableManifest = 'portable.yml';
  CacheRootName = 'SmartCleaner\SetupCache';
  Base64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  HexDigits = '0123456789ABCDEF';

var
  ModePage: TInputOptionWizardPage;
  DirPage: TInputDirWizardPage;
  DownloadPage: TDownloadWizardPage;
  ExtractionPage: TExtractionWizardPage;
  ManifestsFetched: Boolean;
  OnlineMode: Boolean;
  FullOK, PortOK: Boolean;
  LatestFetchErr, PortFetchErr: String;
  FeedVersionFull, FeedFileFull, FeedShaFull: String;
  FeedVersionPort, FeedFilePort, FeedShaPort: String;
  CacheVersion, CacheKind, CacheManifestName, CachePayloadName: String;
  ChosenKind: String; // 'full' | 'port'
  ChosenVersion, ChosenFile, ChosenSha, ChosenManifestName: String;
  ChosenFromCache: Boolean;
  PayloadPath: String;
  FinishSummary: String;

function FeedBase(): String;
begin
  Result := '{#FeedBaseUrl}';
end;

function CacheBaseDir(): String;
begin
  Result := GetEnv('LOCALAPPDATA');
  if Result = '' then Result := ExpandConstant('{tmp}');
  Result := AddBackslash(Result) + CacheRootName;
end;

function StripQuotes(const S: String): String;
begin
  Result := S;
  if (Length(Result) >= 2) and (Result[1] = '''') and
     (Result[Length(Result)] = '''') then
    Result := Copy(Result, 2, Length(Result) - 2)
  else if (Length(Result) >= 2) and (Result[1] = '"') and
     (Result[Length(Result)] = '"') then
    Result := Copy(Result, 2, Length(Result) - 2);
end;

function ParseManifest(const FileName: String; var Version, Payload,
  Sha: String): Boolean;
var
  Lines: TStringList;
  I: Integer;
  Raw, L, PathV, UrlV, TopSha, NestedSha: String;
begin
  Version := ''; Payload := ''; Sha := '';
  PathV := ''; UrlV := ''; TopSha := ''; NestedSha := '';
  Lines := TStringList.Create;
  try
    try
      Lines.LoadFromFile(FileName);
    except
      Result := False;
      Exit;
    end;
    for I := 0 to Lines.Count - 1 do
    begin
      Raw := Lines[I];
      L := Trim(Raw);
      if (Pos('version:', L) = 1) and (Version = '') then
        Version := StripQuotes(Trim(Copy(L, 9, MaxInt)))
      else if (Pos('path:', L) = 1) and (PathV = '') then
        PathV := StripQuotes(Trim(Copy(L, 6, MaxInt)))
      else if (Pos('- url:', L) = 1) and (UrlV = '') then
        UrlV := StripQuotes(Trim(Copy(L, 7, MaxInt)))
      else if Pos('sha512:', L) = 1 then
      begin
        if (Length(Raw) > 0) and (Raw[1] = ' ') then
        begin
          if NestedSha = '' then
            NestedSha := StripQuotes(Trim(Copy(L, 8, MaxInt)));
        end
        else if TopSha = '' then
          TopSha := StripQuotes(Trim(Copy(L, 8, MaxInt)));
      end;
    end;
  finally
    Lines.Free;
  end;
  if PathV <> '' then Payload := PathV else Payload := UrlV;
  if TopSha <> '' then Sha := TopSha else Sha := NestedSha;
  Result := (Version <> '') and (Payload <> '') and (Sha <> '');
  if (Pos('/', Payload) > 0) or (Pos('\', Payload) > 0) or
     (Pos('..', Payload) > 0) then
    Result := False;
end;

function Base64ToHex(const B64: String): String;
var
  I, Acc, Bits, V, J: Integer;
begin
  Result := '';
  Acc := 0; Bits := 0;
  for I := 1 to Length(B64) do
  begin
    if B64[I] = '=' then Break;
    V := Pos(B64[I], Base64Alphabet) - 1;
    if V < 0 then Continue;
    Acc := (Acc shl 6) or V;
    Bits := Bits + 6;
    if Bits >= 8 then
    begin
      Bits := Bits - 8;
      J := (Acc shr Bits) and $FF;
      Result := Result + HexDigits[(J shr 4) + 1] + HexDigits[(J and $F) + 1];
    end;
  end;
end;

function VersionPart(const V: String; Index: Integer): Integer;
var
  SL: TStringList;
begin
  Result := 0;
  SL := TStringList.Create;
  try
    SL.Delimiter := '.';
    SL.StrictDelimiter := True;
    SL.DelimitedText := V;
    if (Index >= 0) and (Index < SL.Count) then
      Result := StrToIntDef(Trim(SL[Index]), 0);
  finally
    SL.Free;
  end;
end;

function CompareVersions(const A, B: String): Integer;
var
  I, PA, PB: Integer;
begin
  for I := 0 to 2 do
  begin
    PA := VersionPart(A, I);
    PB := VersionPart(B, I);
    if PA < PB then begin Result := -1; Exit; end;
    if PA > PB then begin Result := 1; Exit; end;
  end;
  Result := 0;
end;

function LooksLikeVersion(const S: String): Boolean;
begin
  Result := (Length(S) >= 5) and (Pos('.', S) > 0) and
    (VersionPart(S, 0) + VersionPart(S, 1) + VersionPart(S, 2) >= 0);
end;

procedure ScanCache();
var
  FindRec: TFindRec;
  DirPath, ManifestPath, V, PV, PS: String;
  Best: String;
begin
  CacheVersion := ''; CacheKind := '';
  CacheManifestName := ''; CachePayloadName := '';
  Best := '';
  if not DirExists(CacheBaseDir()) then Exit;
  if FindFirst(CacheBaseDir() + '\*', FindRec) then
  try
    repeat
      if (FindRec.Name <> '.') and (FindRec.Name <> '..') and
         DirExists(CacheBaseDir() + '\' + FindRec.Name) and
         LooksLikeVersion(FindRec.Name) then
      begin
        if (Best = '') or (CompareVersions(FindRec.Name, Best) > 0) then
          Best := FindRec.Name;
      end;
    until not FindNext(FindRec);
  finally
    FindClose(FindRec);
  end;
  if Best = '' then Exit;
  DirPath := CacheBaseDir() + '\' + Best;
  if FileExists(DirPath + '\' + LatestManifest) then
  begin
    ManifestPath := DirPath + '\' + LatestManifest;
    V := ''; PV := ''; PS := '';
    if ParseManifest(ManifestPath, V, PV, PS) and
       FileExists(DirPath + '\' + PV) then
    begin
      CacheVersion := V; CacheKind := 'full';
      CacheManifestName := LatestManifest; CachePayloadName := PV;
      Exit;
    end;
  end;
  if FileExists(DirPath + '\' + PortableManifest) then
  begin
    ManifestPath := DirPath + '\' + PortableManifest;
    V := ''; PV := ''; PS := '';
    if ParseManifest(ManifestPath, V, PV, PS) and
       FileExists(DirPath + '\' + PV) then
    begin
      CacheVersion := V; CacheKind := 'port';
      CacheManifestName := PortableManifest; CachePayloadName := PV;
    end;
  end;
end;

procedure FetchManifests();
var
  Tmp: String;
  FV, FF, FS, PV, PF, PS: String;
begin
  FullOK := False; PortOK := False;
  OnlineMode := False;
  LatestFetchErr := ''; PortFetchErr := '';
  Tmp := ExpandConstant('{tmp}');

  try
    Log('Fetching latest manifest from: ' + FeedBase() + LatestManifest);
    DownloadTemporaryFile(FeedBase() + LatestManifest, LatestManifest, '', nil);
    if ParseManifest(Tmp + '\' + LatestManifest, FV, FF, FS) then
    begin
      FullOK := True; OnlineMode := True;
      FeedVersionFull := FV; FeedFileFull := FF; FeedShaFull := FS;
      Log('latest.yml OK: version=' + FV + ', payload=' + FF);
    end
    else
    begin
      LatestFetchErr := 'Manifest parsing failed (invalid schema or path).';
      Log('latest.yml parse error');
    end;
  except
    LatestFetchErr := GetExceptionMessage;
    Log('latest.yml fetch failed: ' + LatestFetchErr);
  end;

  try
    Log('Fetching portable manifest from: ' + FeedBase() + PortableManifest);
    DownloadTemporaryFile(FeedBase() + PortableManifest, PortableManifest, '', nil);
    if ParseManifest(Tmp + '\' + PortableManifest, PV, PF, PS) then
    begin
      PortOK := True; OnlineMode := True;
      FeedVersionPort := PV; FeedFilePort := PF; FeedShaPort := PS;
      Log('portable.yml OK: version=' + PV + ', payload=' + PF);
    end
    else
    begin
      PortFetchErr := 'Manifest parsing failed (invalid schema or path).';
      Log('portable.yml parse error');
    end;
  except
    PortFetchErr := GetExceptionMessage;
    Log('portable.yml fetch failed: ' + PortFetchErr);
  end;

  if not OnlineMode then
    ScanCache();
end;

procedure OnModeActivate(Sender: TWizardPage);
begin
  if ManifestsFetched then Exit;
  ManifestsFetched := True;
  ModePage.SubCaptionLabel.Caption := '…';
  FetchManifests();
  if OnlineMode then
  begin
    if FullOK and PortOK then
      ModePage.SubCaptionLabel.Caption :=
        FmtMessage(CustomMessage('ModeOnline'), [FeedVersionFull, FeedVersionPort])
    else if FullOK then
      ModePage.SubCaptionLabel.Caption :=
        FmtMessage(CustomMessage('ModeOnline'), [FeedVersionFull, '—'])
    else
      ModePage.SubCaptionLabel.Caption :=
        FmtMessage(CustomMessage('ModeOnline'), ['—', FeedVersionPort]);
  end
  else if CacheVersion <> '' then
    ModePage.SubCaptionLabel.Caption :=
      FmtMessage(CustomMessage('ModeCacheOnly'), [CacheVersion, CacheKind])
  else
    ModePage.SubCaptionLabel.Caption := CustomMessage('ModeNoSource');
end;

function OnModeNext(Sender: TWizardPage): Boolean;
begin
  Result := False;
  ChosenKind := ''; ChosenFromCache := False;
  if ModePage.Values[0] then ChosenKind := 'full'
  else if ModePage.Values[1] then ChosenKind := 'port'
  else
  begin
    MsgBox('Please choose Full Installation or Portable Version.',
      mbError, MB_OK);
    Exit;
  end;
  if OnlineMode then
  begin
    if (ChosenKind = 'full') and FullOK then
    begin
      ChosenVersion := FeedVersionFull; ChosenFile := FeedFileFull;
      ChosenSha := FeedShaFull; ChosenManifestName := LatestManifest;
    end
    else if (ChosenKind = 'port') and PortOK then
    begin
      ChosenVersion := FeedVersionPort; ChosenFile := FeedFilePort;
      ChosenSha := FeedShaPort; ChosenManifestName := PortableManifest;
    end
    else
    begin
      if (ChosenKind = 'full') then
        MsgBox('Full Installation is not available from the release feed.' + #13#10#13#10 +
          'Target URL: ' + FeedBase() + LatestManifest + #13#10 +
          'Diagnostic: ' + LatestFetchErr + #13#10#13#10 +
          'Please choose Portable Version or verify your internet connection.',
          mbError, MB_OK)
      else
        MsgBox('Portable Version is not available from the release feed.' + #13#10#13#10 +
          'Target URL: ' + FeedBase() + PortableManifest + #13#10 +
          'Diagnostic: ' + PortFetchErr + #13#10#13#10 +
          'Please choose Full Installation or verify your internet connection.',
          mbError, MB_OK);
      Exit;
    end;
  end
  else
  begin
    if (CacheVersion = '') or (CacheKind <> ChosenKind) then
    begin
      MsgBox('Could not reach the release feed and no verified offline cache was found.' + #13#10#13#10 +
        'Network Diagnostics:' + #13#10 +
        '• Feed Base: ' + FeedBase() + #13#10 +
        '• Full (latest.yml): ' + LatestFetchErr + #13#10 +
        '• Portable (portable.yml): ' + PortFetchErr + #13#10#13#10 +
        'Please check your internet connection, proxy, or firewall, then restart Setup.',
        mbError, MB_OK);
      Exit;
    end;
    ChosenFromCache := True;
    ChosenVersion := CacheVersion; ChosenFile := CachePayloadName;
    ChosenManifestName := CacheManifestName;
    if not ParseManifest(CacheBaseDir() + '\' + CacheVersion + '\' +
       ChosenManifestName, FeedVersionFull, FeedFileFull, ChosenSha) then
    begin
      MsgBox('The cached manifest failed validation. Reconnect and restart Setup.',
        mbError, MB_OK);
      Exit;
    end;
    PayloadPath := CacheBaseDir() + '\' + CacheVersion + '\' + ChosenFile;
  end;
  if ChosenKind = 'port' then
    DirPage.Values[0] := ExpandConstant('{userdocs}\{#MyAppName}');
  Result := True;
end;

function OnDirShouldSkip(Sender: TWizardPage): Boolean;
begin
  Result := ChosenKind <> 'port';
end;

function PathStartsWith(const Path, Prefix: String): Boolean;
var
  P, Q: String;
begin
  P := Uppercase(AddBackslash(RemoveBackslashUnlessRoot(Path)));
  Q := Uppercase(AddBackslash(RemoveBackslashUnlessRoot(Prefix)));
  Result := (Length(P) >= Length(Q)) and (Copy(P, 1, Length(Q)) = Q);
end;

function IsProtectedLocation(const Dir: String): Boolean;
begin
  Result :=
    PathStartsWith(Dir, ExpandConstant('{autopf}')) or
    PathStartsWith(Dir, ExpandConstant('{autopf32}')) or
    PathStartsWith(Dir, ExpandConstant('{win}'));
end;

function OnDirNext(Sender: TWizardPage): Boolean;
var
  D: String;
begin
  Result := False;
  D := RemoveBackslashUnlessRoot(Trim(DirPage.Values[0]));
  if D = '' then
  begin
    MsgBox('Please choose a folder for the portable copy.', mbError, MB_OK);
    Exit;
  end;
  if FileExists(AddBackslash(D) + '{#MyAppExeName}') then
  begin
    MsgBox('That folder already contains a copy of the app:'#13#10 + D + #13#10#13#10 +
      'Pick an empty folder to avoid mixing two versions.',
      mbError, MB_OK);
    Exit;
  end;
  if IsProtectedLocation(D) then
  begin
    if MsgBox('That location needs admin rights for every run and is a poor ' +
      'home for a portable folder:'#13#10 + D + #13#10#13#10 +
      'Recommended: press No and pick a folder you own (Documents, USB stick).' + #13#10#13#10 +
      'Extract the portable copy here anyway?',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2) <> IDYES then
      Exit;
  end;
  DirPage.Values[0] := D;
  Result := True;
end;

procedure VerifyPayloadHash();
var
  PS, Args, HashFile, Got, Want: String;
  Code: Integer;
  Lines: TStringList;
begin
  PS := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  if not FileExists(PS) then
    RaiseException('PowerShell is required for integrity verification but was not found.');
  HashFile := ExpandConstant('{tmp}\payload.sha512');
  DeleteFile(HashFile);
  Args := '-NoProfile -ExecutionPolicy Bypass -Command "(Get-FileHash ' +
    '-Algorithm SHA512 -LiteralPath ''' + PayloadPath + ''').Hash | ' +
    'Out-File -LiteralPath ''' + HashFile + ''' -NoNewline -Encoding ascii"';
  if not Exec(PS, Args, '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    RaiseException('Integrity check could not run (PowerShell failed with exit code ' + IntToStr(Code) + '). Aborting.');
  if not FileExists(HashFile) then
    RaiseException('Integrity check produced no result at ' + HashFile + '. Aborting.');
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(HashFile);
    if Lines.Count = 0 then
      RaiseException('Integrity check produced empty output. Aborting.');
    Got := Uppercase(Trim(Lines[0]));
  finally
    Lines.Free;
  end;
  DeleteFile(HashFile);
  Want := Base64ToHex(ChosenSha);
  Log('Payload SHA-512 check: Computed=' + Got + ', Expected=' + Want);
  if (Got = '') or (Got <> Want) then
  begin
    DeleteFile(PayloadPath);
    RaiseException(
      'INTEGRITY FAILURE: the downloaded package does not match its manifest SHA-512.' + #13#10#13#10 +
      'Expected: ' + Want + #13#10 +
      'Computed: ' + Got + #13#10#13#10 +
      'The corrupted file was deleted and nothing was installed. ' +
      'Please retry — if this persists, the network connection or feed may be compromised.');
  end;
  Log('SHA-512 verified successfully for ' + ChosenFile);
end;

procedure WriteCache();
var
  Base, Dest, Find: String;
  FindRec: TFindRec;
begin
  try
    Base := CacheBaseDir();
    Dest := Base + '\' + ChosenVersion;
    ForceDirectories(Dest);
    FileCopy(ExpandConstant('{tmp}\' + ChosenManifestName),
      Dest + '\' + ChosenManifestName, False);
    FileCopy(PayloadPath, Dest + '\' + ChosenFile, False);
    if FindFirst(Base + '\*', FindRec) then
    try
      repeat
        if (FindRec.Name <> '.') and (FindRec.Name <> '..') and
           DirExists(Base + '\' + FindRec.Name) and
           (FindRec.Name <> ChosenVersion) then
        begin
          Find := Base + '\' + FindRec.Name;
          Log('Pruning old cache: ' + Find);
          DelTree(Find, True, True, True);
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  except
    Log('Cache write failed (non-fatal): ' + GetExceptionMessage);
  end;
end;

procedure RunFullPayload();
var
  Code: Integer;
  InstalledExe: String;
begin
  Log('Executing Full NSIS installer: ' + PayloadPath);
  if not Exec(PayloadPath, '', '', SW_SHOW, ewWaitUntilTerminated, Code) then
    RaiseException('Could not start the Full installer: ' + PayloadPath);
  if Code <> 0 then
    RaiseException('The Full installer did not complete ' +
      '(exit code ' + IntToStr(Code) + '). Nothing was changed by Setup.');
  InstalledExe := ExpandConstant('{autopf}\{#MyAppName}\{#MyAppExeName}');
  if FileExists(InstalledExe) then
  begin
    if MsgBox('Full installation of version ' + ChosenVersion +
      ' completed.' + #13#10#13#10 + 'Launch {#MyAppName} now?',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON1) = IDYES then
    begin
      if not ShellExec('', InstalledExe, '', '', SW_SHOW, ewNoWait, Code) then
        Log('Launch failed (non-fatal)');
    end;
  end
  else
    MsgBox('Full installation of version ' + ChosenVersion + ' completed. ' +
      'Launch it from the Start Menu.', mbInformation, MB_OK);
end;

procedure ExtractPortablePayload();
var
  Dest: String;
  Code: Integer;
begin
  Dest := DirPage.Values[0];
  Log('Extracting Portable ZIP to: ' + Dest);
  ForceDirectories(Dest);
  ExtractionPage.Clear;
  ExtractionPage.Add(PayloadPath, Dest, True);
  ExtractionPage.ShowArchiveInsteadOfFile := True;
  ExtractionPage.Show;
  try
    ExtractionPage.Extract;
  finally
    ExtractionPage.Hide;
  end;
  if ExtractionPage.AbortedByUser then
    RaiseException('Extraction cancelled. The folder may be incomplete — delete it and retry.');
  if not FileExists(AddBackslash(Dest) + '{#MyAppExeName}') then
    RaiseException('Extraction finished but the application executable is missing at: ' +
      AddBackslash(Dest) + '{#MyAppExeName}');
  if not FileExists(AddBackslash(Dest) + 'portable.dat') then
    RaiseException('Extraction finished but portable marker (portable.dat) is missing.');
  Log('Portable payload successfully extracted to ' + Dest);
  if MsgBox('Portable version ' + ChosenVersion + ' extracted to:' + #13#10 +
    Dest + #13#10#13#10 + 'Launch {#MyAppName} now?',
    mbConfirmation, MB_YESNO or MB_DEFBUTTON1) = IDYES then
  begin
    ShellExec('', AddBackslash(Dest) + '{#MyAppExeName}', '', '', SW_SHOW, ewNoWait, Code);
  end;
end;

procedure DoDownloadPayload();
var
  DlUrl: String;
begin
  DlUrl := FeedBase() + ChosenFile;
  PayloadPath := ExpandConstant('{tmp}\' + ChosenFile);
  DeleteFile(PayloadPath);
  Log('Downloading payload: ' + DlUrl + ' -> ' + PayloadPath);
  DownloadPage.Clear;
  DownloadPage.Add(DlUrl, ChosenFile, '');
  DownloadPage.ShowBaseNameInsteadOfUrl := True;
  DownloadPage.Show;
  try
    try
      DownloadPage.Download;
    except
      RaiseException('Payload download failed from ' + DlUrl + #13#10#13#10 +
        'Error: ' + GetExceptionMessage());
    end;
  finally
    DownloadPage.Hide;
  end;
  if DownloadPage.AbortedByUser then
    RaiseException('Download was cancelled by user.');
  if not FileExists(PayloadPath) then
    RaiseException('Download finished but payload file is missing at: ' + PayloadPath);
  Log('Payload downloaded successfully: ' + PayloadPath);
end;

procedure FailClosed(const Msg: String);
begin
  MsgBox(Msg + #13#10#13#10 + 'Setup will now exit. Nothing was installed.',
    mbError, MB_OK);
  Abort;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    try
      if not ChosenFromCache then
      begin
        DoDownloadPayload();
        VerifyPayloadHash();
        WriteCache();
      end
      else
      begin
        VerifyPayloadHash();
      end;
      if ChosenKind = 'full' then
        RunFullPayload()
      else
        ExtractPortablePayload();
      if ChosenFromCache then
        FinishSummary := 'Version ' + ChosenVersion + ' was installed from the verified on-disk cache (offline).'
      else
        FinishSummary := 'Version ' + ChosenVersion + ' was downloaded from the release feed and verified.';
    except
      FailClosed(GetExceptionMessage());
    end;
  end
  else if CurStep = ssDone then
  begin
    if FinishSummary <> '' then
      WizardForm.FinishedLabel.Caption := FinishSummary;
  end;
end;

procedure InitializeWizard();
begin
  ModePage := CreateInputOptionPage(wpLicense,
    CustomMessage('ModeCaption'), CustomMessage('ModeDesc'),
    CustomMessage('ModeSub'), True, False);
  ModePage.Add(CustomMessage('ModeFull'));
  ModePage.Add(CustomMessage('ModePort'));
  ModePage.Values[0] := True;
  ModePage.OnActivate := @OnModeActivate;
  ModePage.OnNextButtonClick := @OnModeNext;

  DirPage := CreateInputDirPage(ModePage.ID,
    CustomMessage('DirCaption'), CustomMessage('DirDesc'),
    CustomMessage('DirSub'), False, '');
  DirPage.Add(CustomMessage('DirPrompt'));
  DirPage.OnNextButtonClick := @OnDirNext;
  DirPage.OnShouldSkipPage := @OnDirShouldSkip;

  DownloadPage := CreateDownloadPage(
    CustomMessage('DlCaption'), CustomMessage('DlDesc'), nil);
  ExtractionPage := CreateExtractionPage(
    CustomMessage('ExCaption'), CustomMessage('ExDesc'), nil);
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  ManifestsFetched := False;
  OnlineMode := False;
  ChosenFromCache := False;
  FinishSummary := '';
  if not FileExists(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe')) then
  begin
    MsgBox('Windows PowerShell is required for integrity verification but was ' +
      'not found. Setup cannot continue.', mbError, MB_OK);
    Result := False;
  end;
end;
