# 검증 로그 (verification_log.md)

> `research-verification` 스킬의 적대적 재검증 패스를 이 레포에 처음 적용한 기록.
> 이 레포는 스킬 정착 이전(2026-09-06)에 작성되었고, 검증 로그가 없었다.
> 재검증 세션: 2026-09-09. 원 작성자와 다른 마음가짐으로 — "이미 근거 등급이
> 매겨져 있으니 믿을만하다"가 아니라 "이 문서의 모든 것이 틀렸을 수 있다고
> 가정하고 하나씩 재확인한다" — 모든 비자명한 주장을 재확인했다.

## 범위

레포 내 `.md` 파일은 `docs/05_hwp_core_parsing.md`, `docs/07_hwp_automation_surface.md`
**2개뿐**이며(Glob으로 확인), **2개 모두 전체를 읽고 재검증했다** — "N개 중 M개만
확인" 없이 완료.

**저장소 구조 관련 비고(오류 아님, 참고사항)**: 두 문서 모두 본문에서 `docs/06`을
"참고"·"상세 기록"으로 여러 차례 인용하지만(`docs/05` §2), 이 레포에는 `docs/06`
파일 자체가 존재하지 않는다(Glob으로 확인, 커밋 이력도 `05`/`07` 두 파일만 추가된
단일 커밋). 번호가 05, 07로 건너뛰는 것으로 보아 00~04, 06은 앞으로 작성될
계획된 문서로 추정되며, 이건 사실관계 오류가 아니라 "아직 안 쓰인 문서에 대한
전방 참조"이므로 본문을 고치지 않고 여기 기록만 남긴다.

## 검증 방법 요약

- `pefile`(Python) 로 로컬 바이너리의 PE 임포트/익스포트 테이블, 버전 리소스,
  COM Descriptor(#14) 데이터 디렉터리를 직접 재파싱.
- 바이너리 raw byte 검색(ASCII 및 UTF-16LE 양쪽)으로 리터럴 문자열 재대조.
- PowerShell + .NET Reflection으로, 이전 세션이 이미 변환해 스크래치 디렉터리에
  남겨둔 `HwpAutomationInterop.dll`(TypeLibConverter 산출물)을 다시 로드해
  타입/메서드/프로퍼티 시그니처 재확인.
- 이전 세션 Ghidra headless 산출물(`hancom-ghidra-hwpcore/out/*.survey.txt`)을
  다시 읽어 디컴파일 코드 재대조(Ghidra 재실행은 하지 않음 — 산출물이 로컬에
  그대로 남아있어 재실행 없이도 원문 대조 가능했음).
- WebSearch/WebFetch로 문서가 인용한 공개 지식(Expat 릴리스 연도, HWPX/OWPML
  표준 여부)을 한컴 공식 출처 등으로 재확인.

| 문서/섹션 | 검증대상 주장 | 분류 | 근거등급 | 검증방법 | 검증결과 | 비고 |
|---|---|---|---|---|---|---|
| 05 §0 | `Hwp.exe` 임포트는 `mscoree.dll`/`_CorExeMain` 하나뿐, CLR 데이터 디렉터리(#14) RVA `0x2008`/크기 72바이트 | 아키텍처 | (a) | `python3` + `pefile`: `pe.DIRECTORY_ENTRY_IMPORT`, `pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]` 직접 파싱, 대상: `C:\Program Files (x86)\Hnc\Office 2024\HOffice130\Bin\Hwp.exe` | 이상 없음 — 완전 일치 | |
| 05 §0 | 버전 리소스: `ProductName=HWP 2024`, `FileVersion/ProductVersion=13.0.0.3901`, `CompanyName=Hancom Inc(HNC).` 등 | 아키텍처 | (a)→오류 발견 | `pefile`로 `Hwp.exe`의 `pe.FileInfo`(StringFileInfo) 재파싱 | **오류 발견·수정함**: 실제 `ProductName` 필드값은 `HWP`이고, `HWP 2024`는 별도 필드 `FileDescription`의 값이었다. 원문이 두 필드를 혼동해 `ProductName=HWP 2024`로 잘못 표기. `FileVersion/ProductVersion=13.0.0.3901`, `CompanyName`, `LegalCopyright`은 전부 일치. `docs/05_hwp_core_parsing.md`에 정정 각주 추가 | |
| 05 §0 | JS 브리지 문자열(`HwpObject.prototype`, `RegisterViewScrolled`, `HwpWebAddonMessageHandler`, `GetBinDataPath` 등)이 `Hwp.exe`에 리터럴로 임베드 | 로직/아키텍처 | (a) | `Hwp.exe` raw bytes에서 각 문자열 직접 검색(`in data`) | 이상 없음 — 전부 존재 확인 | |
| 05 §0 | 위 JS 메서드 이름이 `docs/07`의 COM 오토메이션 이름과 "일부 겹친다" | 아키텍처 | (b) | PowerShell reflection으로 `HwpAutomationInterop.dll`의 전체 259개 타입의 메서드명을 `ViewScrolled`/`BinData`로 grep | 부분 확인 — `GetBinDataPath`는 `IHwpAutomation`/`HwpAutomationClass`의 실제 COM 메서드로 존재(정확히 겹침). `RegisterViewScrolled`는 COM 쪽에 대응 메서드 없음. 원문이 "일부 겹치는 부분이 있다"고만 썼으므로 과장 아님 — 수정 불필요 | |
| 05 §1 | `HNCFilter.dll`/`HMConvDll.dll`/`HncFilter32.dll`/`HncFilter64.dll`의 OLE `Stg*` API 임포트 표 | 아키텍처/API | (a) | `pefile`로 4개 DLL의 임포트 함수 목록을 표와 대조 | 이상 없음 — 표에 적힌 함수명 전부 해당 DLL에서 실제 임포트 확인 | |
| 05 §1 | `HwpAutomation.dll`이 `HncFoundation.dll`의 `CHncStorage(IStorage*, int)`/`CHncStream::Attach(IStream*, int)`를 링크 | 아키텍처/API | (a) | `pefile`로 `HwpAutomation.dll`의 `HncFoundation.dll` 임포트 mangled name(`??0CHncStorage@@QAE@PAUIStorage@@H@Z`, `?Attach@CHncStream@@QAEHPAUIStream@@H@Z` 등) 직접 조회, 수동 디맹글 | 이상 없음 — 시그니처까지 정확히 일치 | |
| 05 §2 | zlib 카피라이트 문자열(1.1.3/1.2.3 in HNCFilter.dll, 1.2.11+minizip in HncFilter32/64.dll) | 로직 | (a) | raw bytes 검색(ASCII) | 이상 없음 | |
| 05 §2 | `HMConvDll.dll`의 `FUN_10007870`이 zlib inflate 상태머신(`"invalid block type"` 등)과 일치 | 로직 | (a) | `hancom-ghidra-hwpcore/out/HMConvDll.dll.survey.txt` 재열람, 해당 함수 디컴파일 코드 재대조 | 이상 없음 — switch 분기와 에러 문자열 전부 일치 | |
| 05 §2 | `CUnZip@OWPML`/`CZip@OWPML` export, MIME 문자열(`application/hwp+zip` 등) | API | (a) | raw bytes(ASCII/UTF-16LE) 검색 | 이상 없음(`application/hwpml-package+xml`은 ASCII로는 안 잡히고 UTF-16LE로 확인됨 — Ghidra가 유니코드 문자열로 인식한 것과 일치, 오류 아님) | |
| 05 §2 | "HWPX = OWPML 기반 zip+XML 포맷"(기존 등급 (b) 추론) | 아키텍처 | (b)→**(a) 상향** | WebFetch로 한컴 공식 기술 블로그 `tech.hancom.com/hwpxformat/` 재확인 | **등급 상향**: "한글의 표준 포맷 HWPX는 국가 표준(KS X 6101)인 OWPML을 따르는 개방형 문서 포맷", "HWPX는 ZIP 파일 구조를 가진 XML 기반 포맷"이 한컴 공식 출처에 원문 그대로 존재 — (b) 추론이 아니라 (a) 공식 문서 명시로 상향, `docs/05`에 각주 추가 | |
| 05 §3 | Expat 2.0.1 버전/에러 문자열(`expat_2.0.1`, `not well-formed` 등) | 로직 | (a) | raw bytes 검색 — 최초 ASCII 검색은 실패했으나 UTF-16LE로 재검색 시 전부 확인됨 | 이상 없음(인코딩 차이일 뿐, 문자열 자체는 실존) | |
| 05 §3 | Expat 2.0.1은 "2007년경 릴리스"(기존 등급 (c), "재검증 안 함"이라 명시) | 로직 | (c)→**(b) 상향** | WebSearch "Expat XML Parser 2.0.1 release date" | **등급 상향**: 다수 공개 자료가 2007-06-06경 릴리스를 가리킴, 3rd-party 배포 이력 기반이라 완전한 (a)는 아니지만 (c)→(b)로 상향, 각주 추가 | |
| 05 §4 | HWP 시그니처 문자열(`HWP Document File V2.00/V2.10/V3.00` 등)이 `HNCFilter.dll`/`HwpAutomation.dll`/`HwpApp.dll`/`HwpAppModule.dll`에 "동일하게" 존재 | 로직 | (a)→오류 발견 | raw bytes(ASCII/UTF-16LE) 로 4개 바이너리 전부 개별 재검색 | **오류 발견·수정함**: `HwpApp.dll`에는 `V1.10`/`V1.20`/`V2.00`/`V2.10` 문자열이 전혀 없다. 실제로는 `HWP Document File`(버전 없음)과 `HWP Document File V3.00`, `HWP Style File   V3.00`만 존재 — 원문 대비 훨씬 좁은 부분집합. `HwpAppModule.dll`은 원문 주장대로 전체 집합 보유(재확인). `docs/05`에 정정 각주 추가 | |
| 05 §4 | `fnFiltering`의 시그니처와 `formatCode` 디스패치 구조(100=특별 취급, 감지함수 2개) | 로직 | (a) 구조/ (b) 추론→**추론 부분 하향** | `hancom-ghidra-hwpcore/out/HNCFilter.dll.survey.txt`에서 `fnFiltering` 전체 디스패치를 처음부터 끝까지(300~1300 전부) 재열람 | 구조 자체는 (a) 이상 없음. 단 **추론 오류 발견·수정함**: `formatCode==200`도 100과 동일하게 감지 함수 2개(`FUN_101051c0` AND `FUN_10104dd0`)를 쓴다 — "100번만 특별해서 네이티브 HWP일 가능성"이라는 기존 추론은 200번의 존재를 몰랐던 상태에서 나온 것이라 약화됨. (b)에서 사실상 (c)/(d)에 가깝다고 등급 하향 표기, `docs/05`에 정정 각주 추가 | |
| 05 §5 | 서드파티 라이브러리 종합표(zlib 버전 2종, minizip, Expat 2.0.1, MFC140u, MSVC STL, XmlLite) | 로직/API | (a) | 위 개별 항목들 재검증 결과 종합 + `pefile`로 `HMConvDll.dll`의 `mfc140u.dll` 임포트 확인 | 대체로 이상 없음. 단, "익스포트 심볼(`CArchive`, `COleStreamFile`)로도 교차 확인"이라는 표현은 정확히는 "MFC는 ordinal 임포트뿐이라 이름이 없고, Ghidra가 자체 심볼DB로 `CArchive`/`COleStreamFile`을 역주석 단 것"이다(survey.txt의 "IMPORTED/EXTERNAL FUNCTIONS" 섹션에서 재확인). 실질적 결론(MFC14.0을 링크하고 그 사실이 이름 수준까지 대응된다)은 틀리지 않아 본문은 수정하지 않음 — 표현의 정밀도 문제로만 기록 | |
| 07 §1 | `HwpAutomation.tlb` 변환 결과 "총 259개 타입" | 아키텍처 | (a) | PowerShell: `[Reflection.Assembly]::LoadFrom(...HwpAutomationInterop.dll)`, `$asm.GetTypes().Count` | 이상 없음 — 정확히 259 | |
| 07 §2 | `IXHwpDocument.Open(String, Object, Object)` / `SaveAs` / `Close(Boolean)` 시그니처 | API | (a) | 위 어셈블리에서 `IXHwpDocument` 타입의 메서드 리스트 reflection | 이상 없음 — 시그니처 문자 그대로 일치 | |
| 07 §2 | `HFileOpen`/`HInsertFile` 파라미터 세트 필드 | API | (a) | reflection으로 프로퍼티 목록 확인 | 이상 없음 | |
| 07 §3 | `IXHwpSendMail`/`HFileSendMail`/`HFtpUpload`/`HInternet`/`IXHwpODBC`/`HVfsAuthentication` 존재 및 필드 | API | (a) | reflection | 이상 없음 — 필드명/타입까지 전부 일치 | |
| 07 §4 | `HScriptMacro`/`HKeyMacro` 존재, `AKeyMacroDefine`/`AScrMacroSecurityDlg` 등 액션 상수 문자열 | API/로직 | (a) | reflection + `HwpAppModule.dll` raw bytes 검색 | 이상 없음 | |
| 07 §4 | `HwpApp.dll`/`HwpAppModule.dll` PE 임포트에 `HncVBA.dll` 없음, 문자열 테이블에 `"HncVBA"` 리터럴 없음 | 아키텍처 | (a) | `pefile`로 두 DLL의 임포트 DLL 목록 확인 + raw bytes(ASCII/UTF-16LE) 검색 | 이상 없음 — 둘 다 확인 | |
| 07 §4 | `HncVBA.dll` 익스포트 2298개, 임포트는 `HncVBAWForms.dll`/`TypeLibCapsuler.dll`/표준 MSVC·COM뿐 | 아키텍처 | (a)→오류 발견 | `pefile`로 `HncVBA.dll`의 `DIRECTORY_ENTRY_EXPORT`/`DIRECTORY_ENTRY_IMPORT` 재카운트 | 익스포트 2298개는 정확히 일치(이상 없음). **오류 발견·수정함**: 임포트 목록에 `HncFoundation.dll`(Hancom 내부 공용 라이브러리)과 `SHLWAPI.dll`이 빠져 있었다 — "표준 MSVC 런타임/COM만"이라는 서술이 부정확. `docs/07`에 정정 각주 추가 | |
| 07 §5 | `HAICommand` 필드(`CommandID`, `ExtractionPath`, `ExtractionOutputPath`, `ExtractionOption`, `ResultPath` 등) | API | (a) | reflection | 이상 없음 — 타입까지 정확히 일치 | |
| 07 §6 | `HwpAppModule.dll`이 `MAPI32.dll`/`WS2_32.dll`/`WININET.dll`/`urlmon.dll`/`mscoree.dll`를 실제로 링크 | 아키텍처 | (a) | `pefile`로 임포트 DLL 목록 재확인 | 이상 없음 — 5개 전부 확인. `HwpApp.dll`은 `WININET.dll`/`urlmon.dll`만 있고 `MAPI32.dll`/`WS2_32.dll`은 없음(원문이 `HwpAppModule.dll`만 특정해서 주장했으므로 오류 아님) | |
| 07 §2 (부가) | `HAction`/`HParameterSet` 인터페이스 실존 | API | (a) | reflection으로 타입명 조회 | 이상 없음 | |

## 요약

- 검증 대상 문서: **2/2 전부 확인 완료**(부분 확인 아님).
- 발견·수정한 오류: **4건**
  1. `docs/05` §0 — `Hwp.exe` 버전 리소스 `ProductName`/`FileDescription` 혼동
  2. `docs/05` §4 — `formatCode==100`만 특별하다는 추론이 실제로는 200도 동일 구조라 약화됨
  3. `docs/05` §4 — `HwpApp.dll`이 다른 바이너리들과 "동일한" HWP 시그니처 문자열 집합을 갖는다는 주장이 과장(실제로는 좁은 부분집합)
  4. `docs/07` §4 — `HncVBA.dll` 임포트 목록에서 `HncFoundation.dll`/`SHLWAPI.dll` 누락
- 등급을 상향한 항목: **2건**(HWPX/OWPML 공식 근거 (b)→(a), Expat 2.0.1 릴리스 연도 (c)→(b))
- 나머지 확인한 주장(약 20건)은 전부 재실측/재대조 결과 이상 없음.
- 미해결로 남긴 것: 두 문서 자체가 이미 "미확인(d)"으로 명시한 항목들(예: `formatCode`↔실제 파일 포맷 매핑, Expat 호출 콜그래프, VBA 자동 실행 경로, `HAICommand` 실제 동작)은 이번 재검증에서도 새로 확증하지 못했다 — 재검증 범위는 "기존 주장이 사실과 일치하는가"였지, 기존에 미확인으로 남긴 열린 질문 자체를 해소하는 것은 범위 밖이었다.
