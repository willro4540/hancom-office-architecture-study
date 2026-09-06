# 07. HwpAutomation — COM/OLE 오토메이션 표면 분석

> 분석 대상: `HwpAutomation.dll` + 동일 폴더의 `HwpAutomation.tlb`(타입 라이브러리).
> 근거 등급 체계는 `docs/05` 서두와 동일: (a) 이번 세션 직접 확인, (b) 고신뢰
> 추론, (c) 3rd-party 근거만, (d) 미확인.

## 1. 타입 라이브러리를 실제로 추출해서 인터페이스 목록을 확보함 (a)

Ghidra는 `.tlb`(COM 타입 라이브러리, MSFT 바이너리 포맷)를 직접 파싱하는
기능이 없어, 대신 .NET 표준 API인
`System.Runtime.InteropServices.TypeLibConverter.ConvertTypeLibToAssembly`를
PowerShell(.NET Framework 4.x 기반)로 호출해 `HwpAutomation.tlb`를 실제로
COM-인터롭 어셈블리로 변환하고, `System.Reflection`으로 그 어셈블리를 열어
인터페이스/메서드 목록을 뽑았다. 이는 "타입 라이브러리에 선언된 그대로"를
정확히 뽑아내는 결정적(deterministic) 변환이므로 (a) 등급으로 채택한다.

결과: **총 259개 타입**(대부분 `dispinterface`/coclass), 그중 사람이 읽을 수
있는 이름의 자동화 오브젝트가 약 230여 개. 전체 목록은 매우 방대하므로(문서
편집·표·양식·그리기·맞춤법 등 워드프로세서 기능 전반을 그대로 노출) 여기서는
**보안 관점에서 눈에 띄는 것만** 추린다. 전체 인터페이스 이름 목록은
`C:\Users\user\AppData\Local\Temp\claude-research\hancom-ghidra-hwpcore\tlb\HwpAutomationInterop.dll`
(로컬 스크래치 산출물, 저장소에는 커밋하지 않음)에서 재추출 가능.

## 2. 파일 열기/삽입 — "임의 파일 열기"가 코드 레벨로 확인됨 (a)

`IXHwpDocument` 인터페이스의 실제 메서드 시그니처를 리플렉션으로 직접
확인했다:

```
Boolean Open(String filename, Object Format, Object arg)
Boolean SaveAs(String Path, Object Format, Object arg)
Boolean Close(Boolean isDirty)
```

즉 COM 오토메이션 클라이언트(로컬에서 `CoCreateInstance`/자동화로
`HwpAutomation`을 붙잡을 수 있는 아무 프로세스)는 GUI 없이 임의의 로컬 경로를
`Open()`으로 열 수 있다 — **이건 추론이 아니라 타입 라이브러리에 실제로
선언된 메서드 시그니처를 읽은 결과다(a)**.

추가로 파라미터 세트 오브젝트 `HFileOpen`(get/set `OpenFileName`,
`OpenFormat`, `OpenReadOnly`, `OpenFlag` 등)과 `HInsertFile`(get/set
`filename`, `FileFormat`, `FileArg`)도 확인됨(a) — Hancom 오토메이션 모델은
"파라미터 세트를 채운 뒤 Action ID로 실행"하는 패턴(`HAction`/`HParameterSet`
인터페이스도 실제 존재, a)을 쓰는 것으로 보이며, `IXHwpDocument.Open()`처럼
직접 메서드 호출로도 파일을 열 수 있다.

## 3. 메일/FTP/DB — 네트워크로 뻗어나가는 자동화 표면 (a, 타입 선언 수준)

리플렉션으로 직접 확인한 메서드/필드:

- `IXHwpSendMail.SendMail()` + `To`/`Subject`/`type` 필드, `HFileSendMail`
  (`To`, `Subject`, `Filepath`) — 문서를 첨부해 메일 발송하는 자동화 오브젝트
- `HFtpUpload` — `Server`, `UserName`, `Password`, `Directory`, `filename`,
  `Port` 필드 전부 존재 — FTP 업로드 파라미터 세트
- `HInternet` — `OpenUrlString`, `OpenUrlWhere` — URL 열기
- `IXHwpODBC.Connect(name, connStr)` / `QueryExcute` / `Insert` / `Select` /
  `Delete` / `UpDate` / `GetDataByNum` / `GetDataByName` — ODBC 데이터베이스
  연결/쿼리 자동화
- `HVfsAuthentication.AuthenticationURL` — 가상 파일시스템/클라우드 인증용
  URL 필드로 추정(b — 필드 이름 기반 추론, 실제 동작은 미확인)

이 자체가 "취약점"은 아니다(오피스 제품군의 메일머지/자동화 기능은
공개적으로도 존재가 알려져 있음). 다만 **로컬에서 이 COM 오브젝트를
자동화할 수 있는 어떤 프로세스든 GUI 확인 없이 파일 열기+메일 발송/FTP
업로드/URL 오픈을 조합할 수 있는 표면이 실제로 타입 라이브러리에 선언되어
있다는 사실**은 이번 세션에서 코드(타입 정보) 근거로 확인됐다(a). 이 메서드들
호출 시 사용자 확인 대화상자가 실제로 뜨는지, 어떤 권한 경계가 있는지는
`HwpApp.dll`/`HwpAppModule.dll`의 네이티브 구현부까지 들어가야 하는데 이번
세션에서는 시간 제약상 그 구현부 심층 디컴파일은 하지 못했다(미확인).

## 4. 매크로 관련 표면 — VBA 엔진과의 직접적 연결은 이번 세션에 확인 못함

타입 라이브러리에 `HScriptMacro`(`name`, `Detail`, `RepeatCount`, `index`)와
`HKeyMacro`(`name`, `RepeatCount`, `index`) 파라미터 세트 오브젝트가
실존함을 확인했다(a). `HwpAppModule.dll`의 문자열 테이블에서도 대응되는
액션 이름 상수들을 확인했다(a, 문자열 실측):

```
AKeyMacroDefine / AKeyMacroRepeat / AKeyMacroStop
AScrMacroDefine / AScrMacroPlay / AScrMacroPause / AScrMacroStop / AScrMacroRepeat
AScrMacroSecurityDlg   <-- 매크로 "보안" 대화상자 액션이 실제로 존재함
```

`AScrMacroSecurityDlg`라는 액션 이름이 실제로 존재한다는 것은, 이 제품에
Office류의 "매크로 보안 경고/신뢰 센터"에 해당하는 게이트가 최소한
액션 레벨로는 구현되어 있음을 시사한다(b, 강한 정황 — 실제로 파일을 열 때
이 다이얼로그가 항상 뜨는지, 우회 경로가 있는지는 미확인).

한편 이번 세션에서 **직접 확인하지 못한 것**: `HwpApp.dll`/`HwpAppModule.dll`의
PE 임포트 테이블에는 `HncVBA.dll`이 나타나지 않는다(정적 PE 임포트 기준
확인, a) — 즉 이 두 핵심 모듈이 VBA 매크로 엔진(`HncVBA.dll`,
`HncVBAWForms.dll`)을 **정적으로 링크하지는 않는다**. 이것이 "VBA가 파일
열기에서 도달 불가능하다"는 뜻은 아니다 — `LoadLibrary`로 런타임에 동적
로드할 가능성은 여전히 있고, 두 문자열 테이블 전체를 스캔했지만
`"HncVBA"`라는 리터럴 문자열 자체를 찾지 못했다(확인 시도했음, 결과: 못
찾음 — 동적 로드 대상 DLL명이 다른 문자열 조합(레지스트리 조회, config
파일 등)으로 구성될 가능성도 배제 못함). **결론: "파일 열기 → VBA 매크로
자동 실행"이 실제로 가능한 경로인지는 이번 세션에서 확증도 반증도 하지
못했다 — 명시적으로 미확인(d)으로 남긴다.**

`HncVBA.dll` 자체는 임포트 테이블상 `HncVBAWForms.dll`, `TypeLibCapsuler.dll`,
표준 MSVC 런타임/COM만 링크하며 익스포트가 2298개(a, PE 익스포트 테이블
직접 카운트)에 달해 — VBA 호환 엔진치고 상당히 큰 표면이지만, 이번 세션에서
그 내부 구현까지는 분석하지 않았다(범위 밖으로 판단, 시간 제약).

## 5. AI 커맨드 — 2024년형 신규 자동화 표면 (a, 존재만 확인)

`HAICommand` 파라미터 세트 오브젝트가 타입 라이브러리에 실존함을 확인했다:

```
Int32 CommandID / CommandValue
String CommandValueStr
String ExtractionPath / ExtractionOutputPath
Int32 ExtractionOption / ResultPath
```

필드 이름(`ExtractionPath`, `ExtractionOutputPath`)으로 보아 파일
경로를 입력/출력으로 다루는 AI 기능(문서 요약·추출 등으로 추정, Hancom
Office 2024가 AI 기능을 마케팅하는 것과 결이 맞음)이 자동화 표면에 노출되어
있다는 것까지는 확인했다(a, 필드 존재). 실제 `CommandID` 값별 동작, 이
경로 필드들이 실행 시 어떻게 검증되는지는 네이티브 구현부(`HwpAppModule.dll`)
심층 분석이 필요하며 이번 세션에서는 하지 못했다(미확인) — AI 기능이라는
최신성 때문에 특히 주목할 가치가 있는 후속 과제로 남긴다.

## 6. 네트워크/메일 API가 실제로 링크되어 있는지 교차 확인 (a)

`docs/07` §3의 자동화 표면(SendMail/FtpUpload/Internet 등)이 단순히
"타입 라이브러리 선언"으로 그치는 게 아니라 실제 구현체가 해당 API들을
링크하고 있는지 `HwpAppModule.dll`의 PE 임포트 테이블로 교차 확인했다(a):

```
MAPI32.dll   <- 메일 API
WS2_32.dll   <- 소켓/네트워크
WININET.dll, urlmon.dll  <- 인터넷/URL
mscoree.dll  <- .NET 런타임 호스팅 (네이티브 모듈인데도 CLR을 호스팅함)
```

즉 `IXHwpSendMail`/`HFtpUpload`/`HInternet` 같은 타입 라이브러리 선언이
"죽은 코드"가 아니라, 실제로 메일/네트워크 API를 링크한 네이티브 모듈이
뒤에 있다는 것을 임포트 테이블 수준에서 확인했다(a). 다만 각 COM 메서드
호출이 실제로 어떤 임포트 함수를 거쳐 실행되는지의 콜체인 자체는 이번
세션에서 추적하지 못했다(미확인).

## 7. 요약 — 확인됨 vs 미확인

**확인됨(a)**:
- 259개 타입의 방대한 자동화 표면 실존 (타입 라이브러리 직접 변환/리플렉션)
- `IXHwpDocument.Open(filename, ...)` — 임의 파일 열기 메서드 시그니처 실존
- SendMail/FtpUpload/Internet/ODBC 자동화 오브젝트 실존 + `HwpAppModule.dll`이
  MAPI32/WS2_32/WININET/urlmon을 실제로 링크
- `HScriptMacro`/`HKeyMacro` 오브젝트 실존, `AScrMacroSecurityDlg` 액션 실존
  (매크로 보안 게이트가 액션 레벨로는 존재)
- `HwpApp.dll`/`HwpAppModule.dll`은 `HncVBA.dll`을 **정적으로는** 링크하지
  않음
- `HAICommand` 자동화 오브젝트 실존 (2024년형 AI 기능)

**미확인(d) — 다음 세션 과제**:
- 파일 열기 시 VBA 매크로가 자동 실행되는지, 매크로 보안 대화상자를 실제로
  우회할 수 있는 자동화 경로가 있는지
- 각 자동화 메서드 호출 시 실제 사용자 확인 UI가 뜨는지(네이티브 구현부
  심층 분석 필요)
- `HAICommand`의 `CommandID`별 실제 동작과 경로 검증 여부
- COM 오브젝트를 원격(DCOM)으로도 노출하는지, 아니면 로컬 프로세스 자동화로만
  제한되는지(레지스트리 `AppID`/`LaunchPermission` 확인 필요 — 이번 세션에
  레지스트리 조사는 범위 밖으로 두었음)
