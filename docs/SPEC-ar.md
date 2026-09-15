# Smart Cleaner — Original Design Spec (Arabic)

> This is the product owner's original specification, preserved verbatim.
> English working docs: `ARCHITECTURE.md`, `RISK-ENGINE.md`, `SAFETY.md`,
> `QUARANTINE.md`, `DATABASE.md`, `ROADMAP.md`.

أيوه. لو هنصممه صح، أنا أقترح إن البرنامج يبقى Smart Windows Cleaner وليس مجرد Cleaner تقليدي. أهم مبدأ: الـAI يقترح ويحلل، لكن طبقة Safety هي التي تقرر هل الحذف مسموح أم لا.

## Architecture كاملة

```text
┌──────────────────────────────────────────────────────────┐
│                    Windows Desktop UI                    │
│              Electron + React / Tauri + React            │
├──────────────────────────────────────────────────────────┤
│ Dashboard │ Scan │ Results │ Cleanup │ Quarantine │ Logs │
└───────────────────────┬──────────────────────────────────┘
                        │ IPC / Local API
                        ▼
┌──────────────────────────────────────────────────────────┐
│                    Application Core                      │
│                                                          │
│ Scan Manager │ Job Queue │ Settings │ Permissions        │
│ Update       │ Notifications │ Telemetry (optional)      │
└───────────────┬───────────────────┬──────────────────────┘
                │                   │
        ┌───────▼──────┐     ┌──────▼─────────┐
        │ File Scanner │     │  Risk Engine   │
        └───────┬──────┘     └──────┬─────────┘
                │                   │
                ▼                   ▼
        ┌───────────────────────────────────┐
        │       File Intelligence Layer     │
        │                                   │
        │ Metadata │ Hash │ File Type       │
        │ Process  │ Windows │ Software DB   │
        └────────────────┬──────────────────┘
                         │
                         ▼
                ┌────────────────┐
                │ AI Analyzer     │
                │ Optional/Cloud  │
                └────────┬───────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ Safety Verification  │
              │ FINAL GATE           │
              └──────────┬───────────┘
                         │
                  ┌──────▼──────┐
                  │ Quarantine  │
                  └──────┬──────┘
                         │
              ┌──────────▼──────────┐
              │ Delete / Restore    │
              └─────────────────────┘
```

## 1. Windows Layer

البرنامج يحتاج صلاحيات مختلفة حسب المكان الذي يفحصه.

**User mode** — يفحص: `C:\Users\<user>\` ويقدر يتعامل مع: Downloads, AppData, Temp, Desktop, Documents, Browser caches, Application caches.

**Elevated mode** — عند الحاجة فقط: `C:\Windows`, `C:\ProgramData`, `C:\Program Files`, `C:\Program Files (x86)`.

ممنوع إن البرنامج يطلب Administrator طوال الوقت. يطلب elevation فقط لما يحتاجها.

## 2. File Scanner

ده قلب البرنامج. بدل `scan known folders` نعمل **Filesystem Discovery Engine** يفحص الـ drives الموجودة: `C:\`, `D:\`, `E:\` ... ويجمع Metadata فقط في البداية. مثلاً:

```json
{
  "path": "C:\\Users\\User\\AppData\\Local\\Temp\\abc.tmp",
  "size": 1827364,
  "extension": ".tmp",
  "created": "...",
  "modified": "...",
  "accessed": "...",
  "attributes": [],
  "isHidden": true,
  "isSystem": false,
  "owner": "User"
}
```

Scanner لا يحذف أي شيء. هو فقط: **Discover → Analyze → Report**

## 3. File Intelligence Layer

بعد اكتشاف الملف، نبدأ نفهمه.

**A. File Type** — مش اعتمادًا على extension فقط (`.exe`, `.dll`, `.sys`, `.tmp`, `.log`, `.cache`, `.dat`). نستخدم: Extension, MIME/signature, PE headers, Digital signature, File metadata.

**B. Windows Awareness** — نسأل: هل الملف جزء من Windows؟ (System32, WinSxS, DriverStore, Windows\Installer, Windows\servicing). أي شيء حساس يأخذ `PROTECTED` وليس `JUNK` حتى لو كان قديمًا.

**C. Process Awareness** — نفحص هل الملف مستخدم حاليًا (Chrome.exe, Discord.exe, Steam.exe). لو الملف locked أو مستخدم: `IN_USE` ولا نحذفه.

## 4. Software Awareness

ودي من أهم الحاجات اللي هتخلي البرنامج مختلف. نعمل **Installed Software Registry** ونكتشف البرامج المثبتة (Google Chrome, Steam, Adobe, Discord, Visual Studio, NVIDIA, AMD) ثم نربط الملفات بالبرنامج.

مثلاً: `C:\Users\User\AppData\Local\Google\Chrome\...` → Owner: Chrome, Type: Cache, Risk: Low.
لكن: `chrome.dll` → Owner: Chrome, Type: Application Binary, Risk: Critical.

## 5. Risk Engine ⭐

دي أهم طبقة. نظام **Scoring + Hard Rules**. `Risk Score: 0 → 100` — لكن الرقم يكون **Risk of deletion** وليس "مدى الـjunk".

| Score | Classification |
|---|---|
| 0–10 | Very Safe |
| 11–30 | Safe |
| 31–60 | Review |
| 61–85 | Dangerous |
| 86–100 | Protected |

مثال: Temp file (+20 junk indicator, +10 old, +10 temporary extension, -0 system) → Risk = 15 → Safe.
لكن: DLL (+40 executable, +30 application dependency, +20 currently referenced) → Risk = 90 → Protected.

## 6. Hard Safety Rules

دي أعلى من AI. مثلاً:

```text
IF WindowsProtectedPath  => NEVER_DELETE
IF SystemFile            => NEVER_DELETE
IF Driver                => NEVER_DELETE
IF CurrentlyInUse        => NEVER_DELETE
IF SignedCriticalBinary  => NEVER_DELETE
IF UnknownExecutable     => NEVER_AUTO_DELETE
```

حتى لو الـAI قال: "Delete it." — الـSafety Engine يقول: ❌ NO.

## 7. AI Analyzer 🤖

الجزء الذكي. لكن AI مش هيعمل Scan لكل الملفات. بدل: 1,000,000 files → AI، نعمل:

```text
1,000,000 files → Local analysis → 20,000 candidates → Risk Engine → 1,000 ambiguous files → AI
```

الـAI يستقبل metadata وليس الملف نفسه غالبًا:

```json
{
  "path": "C:\\Users\\X\\AppData\\Local\\SomeApp\\cache\\...",
  "size": 734003200,
  "type": "cache",
  "age_days": 183,
  "owner": "SomeApp",
  "signed": false,
  "in_use": false,
  "application_installed": true
}
```

ويطلع:

```json
{
  "classification": "LIKELY_JUNK",
  "confidence": 0.96,
  "reason": "Old application cache",
  "recommendation": "QUARANTINE"
}
```

## 8. الإنترنت مش إجباري

ثلاثة Modes:

- 🟢 **Offline** — كل شيء محلي: Scanner, Risk Engine, Safety, Quarantine, Cleanup.
- 🔵 **Online Intelligence** — يستعلم عن: Unknown application, Unknown file type, Software metadata, Known cache locations.
- 🟣 **AI Cloud** — للحالات الغامضة فقط ("Is this folder likely safe to remove?").

**Cloud AI لا يحصل على صلاحية الحذف.**

## 9. Quarantine System 🛡️

ما تعملش Delete مباشرة. تعمل: `File → Quarantine → Wait → Permanent Delete`.

يُنقل إلى **Quarantine Vault** مع metadata:

```json
{
  "originalPath": "...",
  "quarantinePath": "...",
  "sha256": "...",
  "size": 123456,
  "deletedAt": "...",
  "reason": "Application cache",
  "riskScore": 8
}
```

## 10. Rollback

المستخدم يقدر يقول: Restore — والبرنامج يرجع: `Quarantine → Original Location` مع التأكد من: path still valid, destination doesn't unexpectedly conflict, hash, permissions, disk space.

## 11. Permanent Delete

بعد فترة (1 / 7 / 30 يوم أو Never حسب Settings): `Quarantine → Permanent Delete`. وممكن يكون فيه "Delete permanently now" لكن يحتاج confirmation أقوى.

## 12. Duplicate Detection

`Size → Partial Hash → Full SHA-256`. فنكتشف: Game.iso, Game-copy.iso, Game-old.iso. لكن لا نقول "Delete duplicate" مباشرة — نقول "Potential duplicates" (File A 72.4 GB / File B 72.4 GB / Same SHA-256) ثم المستخدم يختار.

## 13. Large Files Intelligence

بدل Cleaner فقط، البرنامج يبقى **Disk Intelligence**: Largest files (Windows, Applications, Games, Videos, Downloads, Unknown). وممكن يقول: "You have 94 GB of files that haven't been modified in 12 months." **لكن القديم لا يعني Junk** — دي نقطة مهمة جدًا.

## 14. Storage Analyzer

Visualization: `C:\ 476 GB` (Applications 132 GB, Games 118 GB, Windows 42 GB, Users 96 GB, Downloads 31 GB, Other 57 GB) ثم drill-down (Users → User → AppData / Downloads / Videos / ...).

## 15. UI

Dashboard: اسم البرنامج، حجم الـ drive، Potential cleanup، [ Scan Now ].

بعد الـ Scan: "SCAN COMPLETE — 38.7 GB Potentially Reclaimable" مع قائمة (Temporary Files 4.2 GB, Browser Cache 6.8 GB, Application Cache 8.4 GB, Old Installers 5.1 GB) و"⚠ Review Required 14.2 GB".

## 16. Results Page

كل نتيجة يكون لها: Name, Path, Size, Type, Owner, Last Modified, Risk, Reason, Action. مثلاً: "Chrome Cache — 6.2 GB — Risk: VERY LOW — Why? (Cache data, 184 days old, Chrome is installed, Not currently in use) — [ Quarantine ] [ Ignore ]".

وده أفضل بكتير من: "Clean 6.2 GB" من غير تفسير.

## 17. Explainability

كل قرار لازم يكون قابل للتفسير. "Why is this safe?" ويطلع: ✓ Temporary file, ✓ Not a Windows component, ✓ Not an executable, ✓ Not currently in use, ✓ Associated application still exists, ✓ Older than 30 days.

## 18. Ignore Rules

المستخدم ممكن يقول: "Never touch this folder." (مثلاً D:\MyProjects) فتتسجل **User Exclusion**. وكذلك: Ignore this file / Ignore this application / Ignore this folder.

## 19. Audit Log

كل عملية تنظيف تتسجل: التاريخ والوقت، Action, File, Size, Risk, Reason, Engine (Local Rules / AI), Result.

## 20. Architecture التقنية

لو مرتاح مع Electron/React في مشروع Media Downloader، ممكن تستخدم نفس المدرسة:

```text
Desktop
├── Electron
├── React (Dashboard, Scanner, Results, Quarantine, Settings, Logs)
└── Native Core (Scanner, File Analyzer, Process Analyzer, Risk Engine,
                 Safety Engine, Quarantine, Cleanup)
```

للـScanner نفسه أفضل استخدام Native Windows code بدل JavaScript لكل filesystem operations: `Electron/React → IPC → Native Worker → Windows APIs`. والـ Native Worker ممكن يكون **Rust** أو C++. أميل إلى Rust لو المشروع جديد، بسبب memory safety والأمان في التعامل مع filesystem/processes.

## 21. Database

SQLite داخل الجهاز. Tables: files, scan_sessions, risk_assessments, quarantine_items, cleanup_operations, user_exclusions, software, ai_analysis, audit_logs, settings.

مثلاً `files`: id, path, size, mtime, file_type, sha256, owner_app, risk_score, classification, last_scanned.

## 22. AI Service Architecture

لو Online: `Desktop → Local API → Sanitize Metadata → AI Gateway → LLM`.

مهم جدًا: لا ترسل Full personal file contents, Documents, Photos, Passwords, Browser data — إلا لو هناك سبب واضح وموافقة صريحة. الأصل أن الـAI يشوف: metadata, path pattern, file type, application context, risk signals — مع إخفاء اسم المستخدم قدر الإمكان.

## 23. Security Boundary

ودي أهم نقطة في المشروع كله:

```text
                 AI
                  │
                  │ recommendation
                  ▼
            Risk Engine
                  │
                  ▼
           Safety Engine
                  │
             ┌────┴────┐
             │          │
            NO         YES
             │          │
          BLOCK      QUARANTINE
                         │
                         ▼
                    USER CONFIRM
                         │
                         ▼
                    PERMANENT
```

**الـAI عمره ما يبقى هو صاحب القرار النهائي.**

## 24. Self-Protection

البرنامج نفسه يحمي Cleaner.exe وكل مكوناته من accidental deletion / modification / quarantine / cleanup. يكون عندك `Program Files\SmartCleaner\` والـ database/quarantine منفصلين.

## 25. Recovery Mode

لو حصلت مشكلة: `Settings → Recovery → Restore last cleanup` وممكن Restore All — لكن فقط للعناصر الموجودة في quarantine.

## 26. أهم Feature أضيفها: "Deep Scan"

ثلاثة مستويات:

- **Quick Scan** — Known safe junk.
- **Smart Scan** — Filesystem + Software + Cache + Large files + Risk engine.
- **Deep Analysis** — Everything + hashes + process analysis + duplicate detection + AI analysis.

## 27. والنتيجة النهائية

البرنامج مش مجرد 🧹 PC Cleaner بل: **AI-Assisted Windows Storage Intelligence & Safe Cleanup** — عنده 4 وظائف منفصلة:

```text
        ┌──────────────────┐
        │  STORAGE ANALYZER │
        └────────┬─────────┘
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
   CLEANUP              INSIGHTS
       │                   │
       ▼                   ▼
 QUARANTINE            LARGE FILES
       │               DUPLICATES
       ▼               OLD DATA
    ROLLBACK
```

وأنا أنصح بشدة إن أول Version ما تحتويش على AI Cloud أصلًا. ابنِ أولًا Scanner + Risk Engine + Safety Engine + Quarantine + Rollback بشكل ممتاز. بعد ذلك أضف AI كـ second-opinion layer للحالات التي لا يستطيع المحرك المحلي تصنيفها بثقة.

بهذه الطريقة البرنامج لا يحتاج إنترنت لكي يكون مفيدًا، والـAI يبقى إضافة ذكية وليس نقطة فشل أو خطر على ملفات المستخدم.
