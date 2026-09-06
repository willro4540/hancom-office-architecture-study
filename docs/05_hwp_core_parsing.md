# 05. HWP 코어 워드프로세서 바이너리 — 파일 파싱 아키텍처

> 분석 대상: `Hwp.exe`, `HwpApp.dll`, `HwpAppModule.dll`, `HNCFilter.dll`,
> `HncFilter32.dll` / `HncFilter64.dll`, `HMConvDll.dll` (모두
> `C:\Program Files (x86)\Hnc\Office 2024\HOffice130\Bin\`, 버전
> `13.0.0.3901` / "HWP 2024").
>
> **근거 등급**: (a) 이번 세션에서 직접 읽은 디컴파일 코드/문자열/임포트 테이블로 확인,
> (b) 코드+공개문서로 고신뢰 추론, (c) 3rd-party 자료에만 근거(바이너리 미확인),
> (d) 미확인/열린 질문. 이 등급 체계는 `civil3d-architecture-study`,
> `virtualbox-ubuntu-architecture-study`의 관례를 그대로 따름.
>
> **분석 도구**: Ghidra 12.1.3 headless (`analyzeHeadless` + 커스텀 postScript
> `Survey.java`로 임포트/익스포트/문자열/디컴파일 일괄 덤프), 그리고 PE 헤더를 직접
> 파싱하는 자체 Python 스크립트(임포트/익스포트 테이블, CLR 헤더 유무 확인용).
> Ghidra 프로젝트: `C:\Users\user\AppData\Local\Temp\claude-research\hancom-ghidra-hwpcore\`
> (converter 분석 에이전트가 쓰는 `hancom-ghidra\`와는 별도 디렉터리).

## 0. Hwp.exe 자체는 순수 네이티브 실행파일이 아니다 (a, 실측 확인 — 중요한 선행 발견)

`Hwp.exe`의 PE 임포트 테이블을 이번 세션에서 직접 파싱한 결과, 임포트된 DLL은
**`mscoree.dll` 단 하나**이며 임포트 함수도 `_CorExeMain` 하나뿐이다. 추가로 PE
옵셔널 헤더의 데이터 디렉터리 #14(COM Descriptor / CLR 런타임 헤더)를 직접
파싱했더니 RVA `0x2008`, 크기 `72`바이트로 **0이 아님** — 즉 `Hwp.exe`는 .NET
CLR이 로드하는 관리형(managed) 내지 혼합형 어셈블리임을 PE 헤더 수준에서
확증했다(a).

바이너리 내 문자열을 스캔한 결과도 이를 뒷받침한다: `Hnc.Controls.Native`(.NET
네임스페이스로 보이는 문자열), `AssemblyCopyrightAttribute`, `Assembly Version /
1.0.0.0` 같은 어셈블리 속성 문자열, 그리고 놀랍게도 **자바스크립트 코드 조각이
그대로 리터럴 문자열로 임베드**되어 있다:

```
HwpObject.prototype["RegisterViewScrolled"] = function (func) {
    _RegistNotifyMessage(this, ["ViewScrolled"]);
};
...
HwpWebAddonMessageHandler.Initialize();
if (window.onloadHwpObject !== undefined) { window.onloadHwpObject(); };
```

즉 `Hwp.exe`는 (최소한 이 UI 계층에서는) 웹뷰 기반 화면과 네이티브 엔진 사이를
"`HwpObject`"라는 JS 브리지 객체로 연결하는 구조를 갖고 있는 것으로 보인다(a,
문자열 실측). 이 JS 조각의 메서드 이름(`RegisterViewScrolled`,
`GetBinDataPath` 등)은 `docs/07`에서 다루는 COM 오토메이션 오브젝트 모델의
프로퍼티/메서드 이름과 겹치는 부분이 있어, 같은 오토메이션 개념을 웹뷰용 JS와
COM 양쪽으로 노출하는 구조로 추정된다(b, 강한 추론 — JS↔네이티브 브리지의 실제
구현/보안 경계는 이번 세션에서 확인하지 못함, 미확인).

**중요한 방법론적 한계**: Ghidra의 네이티브 x86 디스어셈블러는 `Hwp.exe`에서
`_CorExeMain` 호출부(CLR 로더 스텁)만 보여줄 뿐, 실제 로직(.NET IL 및 임베디드
JS)은 전혀 분석하지 못한다(확인됨 — 실제 실행해서 관찰). 이번 세션에는 .NET
디컴파일러(ILSpy/dnSpy 등)가 없어 `Hwp.exe`의 관리형 코드 자체는 심층 분석하지
못했다 — **명백한 한계로 명시**. 따라서 이후 섹션의 "실제 파일 파싱 로직"
분석은 전부 `Hwp.exe`가 아니라 순수 네이티브 DLL(`HNCFilter.dll`,
`HMConvDll.dll` 등)을 대상으로 한 것이다.

버전 정보(문자열 리소스에서 확인, a): `ProductName=HWP 2024`,
`FileVersion=ProductVersion=13.0.0.3901`, `CompanyName=Hancom Inc(HNC).`,
`LegalCopyright=Copyright 1989. Hancom Inc. All rights reserved.`

## 1. OLE2/CFBF 컴파운드 파일 구조 지원 — 코드 레벨 확인

공개 문서(3rd-party 리버싱 자료 등, HWP 5.0 배포명세)는 HWP 5.x가 OLE2/CFBF
(Compound File Binary Format) 기반이라고 설명한다. 이를 이번 세션에서 실제
임포트 테이블로 확인했다:

| 바이너리 | 확인된 OLE 관련 임포트 | 등급 |
|---|---|---|
| `HNCFilter.dll` | `StgOpenStorage`, `StgOpenStorageOnILockBytes`, `StgIsStorageFile`, `CreateILockBytesOnHGlobal`, `CreateStreamOnHGlobal` | (a) |
| `HMConvDll.dll` | `StgOpenStorage`, `StgCreateDocfileOnILockBytes`, `StgCreateDocfile`, `StgIsStorageFile`, `GetHGlobalFromILockBytes` | (a) |
| `HncFilter32.dll`/`HncFilter64.dll` | `StgOpenStorageOnILockBytes`, `GetHGlobalFromILockBytes`, `CLSIDFromString` | (a) |
| `HwpAutomation.dll` | `HncFoundation.dll`의 `CHncStorage`/`CHncStream` C++ 클래스를 링크 — 생성자 시그니처 `CHncStorage(IStorage*, int)`, `CHncStream::Attach(IStream*, int)` (mangled export name에서 직접 확인) | (a) |

즉 "HWP 5.x는 OLE 구조적 저장소를 쓴다"는 공개 지식은, 적어도 "이 바이너리들이
Windows 표준 구조적 저장소 API(`Stg*`)를 실제로 호출할 수 있게 링크되어
있다"는 수준까지는 이번 세션에서 코드 근거로 확증됐다(a). 다만 **실제 스트림
열거 순서, FileHeader 스트림을 몇 바이트째부터 어떻게 파싱하는지** 같은 세부
디컴파일까지는 이번 세션에서 들어가지 못했다 — 그 부분은 (c)/공개문서 수준으로
남겨둔다(미확인).

## 2. zlib/inflate 기반 압축 — 코드 레벨 확인, 그리고 버전 혼재

`HNCFilter.dll` 문자열 테이블에서 zlib의 카피라이트 배너 문자열을 **그대로**
확인했다(a, 리터럴 문자열 직접 관찰):

```
deflate 1.2.3 Copyright 1995-2005 Jean-loup Gailly
inflate 1.1.3 Copyright 1995-1998 Mark Adler
inflate 1.2.3 Copyright 1995-2005 Mark Adler
```

같은 파일에 서로 다른 zlib 빈티지(1.1.3과 1.2.3) 배너가 동시에 들어있다는
것은, 이 DLL이 여러 시점에 컴파일된 코드/서드파티 소스를 이어붙였을
가능성을 시사한다(b, 추론 — 직접적인 원인은 미확인).

한편 `HncFilter32.dll`/`HncFilter64.dll`(Windows 검색 인덱싱용 IFilter
컴포넌트로 추정, `docs/06`·`docs/07` 참고)에는 **다른** zlib 빈티지와 별도의
unzip 라이브러리가 임베드되어 있다(a, 문자열 실측):

```
inflate 1.2.11 Copyright 1995-2017 Mark Adler
unzip 0.15 Copyright 1998 Gilles Vollant
```

`unzip 0.15 by Gilles Vollant`는 공개적으로 잘 알려진 **minizip**(zlib
contrib 서브프로젝트) 저작자의 실제 저작권 문구다(c — minizip이라는 프로젝트
정체성 자체는 공개 지식과의 대조이고, 이번 세션에 minizip 소스와 바이트 단위
diff는 하지 않았음).

`HMConvDll.dll`에서는 zlib inflate()의 특징적인 상태머신 구조(블록 타입
0/1/2에 따라 분기하는 switch문, `"invalid block type"` 등 zlib 고유 에러
문자열과 정확히 일치)를 실제로 디컴파일해서 확인했다(a, 이번 세션에서 읽은
코드) — `docs/06`에 해당 함수(`FUN_10007870` 등) 상세 기록.

`HNCFilter.dll`의 zip 관련 C++ 클래스 mangled export도 확인했다: `CUnZip@OWPML`,
`CZip@OWPML` (a). **OWPML**(Open Word-Processor Markup Language)이라는
네임스페이스가 실제 코드에 존재한다는 것은, 공개적으로 알려진 "HWPX = OWPML
기반 zip+XML 포맷"이라는 설명과 부합한다(b — 네임스페이스 존재는 (a), 그것이
정확히 "HWPX 표준 임포트/익스포트 담당 클래스"라는 의미 대응은 강한 추론).

리터럴 MIME 문자열도 확인됨(a): `application/hwp+zip`,
`application/hwpml-package+xml` — HWPX가 zip 컨테이너 기반이라는 공개 설명과
일치.

## 3. Expat XML 파서 정적 링크 (a)

`HNCFilter.dll` 문자열에서 Expat XML 파서 특유의 버전/에러 문자열을 다수
확인했다:

```
expat_2.0.1
XML_UNICODE / XML_UNICODE_WCHAR_T
not well-formed (invalid token) / mismatched tag / duplicate attribute ...
```

Expat 2.0.1은 2007년경 릴리스된 구버전이다(c — 릴리스 연도는 공개 자료 기준,
이 세션에서 재검증 안 함). HWPX(zip+XML) 파싱 경로 어딘가에서 이 Expat이
실제로 호출될 것으로 강하게 추정되나(b), 어느 함수가 Expat API를 직접
호출하는지 콜그래프까지는 이번 세션에서 추적하지 못했다(미확인).

## 4. 버전/시그니처 헤더 문자열 (a — 존재 확인, 파싱 로직은 미확인)

여러 바이너리에 HWP 파일 시그니처로 알려진 문자열이 리터럴로 존재함을
확인했다:

- `HNCFilter.dll`: `HWP Document File`, `HWP Document File V2.00 `,
  `V2.10 `, `V3.00 `
- `HwpAutomation.dll`: 위에 더해 `HWP Document File V1.10 `, `V1.20 `,
  `B4HWP Document File V3.00 ` (더 오래된 버전까지 인식 대상에 포함되어 있음을
  시사)
- `HwpApp.dll`/`HwpAppModule.dll`: 위와 동일한 시그니처 집합 재확인

**주의**: 이건 "이런 문자열이 바이너리 안에 존재한다"는 사실만 (a)로 확인한
것이다. "코드가 파일의 정확히 몇 바이트째부터 몇 바이트를 읽어 이 문자열과
비교하는지"(오프셋, 길이, 대소문자 처리 등 실제 파싱 로직)는 이번 세션에서
디컴파일까지 들어가 확인하지 못했다 — **(d) 미확인**으로 명시한다.

`HNCFilter.dll`의 익스포트 함수 `fnFiltering`은 실제로 디컴파일해서 확인했다:

```c
int __cdecl fnFiltering(ushort *srcPath, ushort *dstPath, int formatCode, int arg4)
```

`formatCode` 값(100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100,
1200, 1300 — 10진수로 환산)에 따라 서로 다른 "포맷 감지 함수" →
(감지 성공 시) "포맷 변환 함수" 쌍을 호출하는 디스패치 구조임을 코드 레벨에서
직접 확인했다(a). 예를 들어 `formatCode==100`일 때는 `FUN_10091300` **AND**
(실패 시) `FUN_100852a0` 두 개의 감지 함수를 순차 시도한 뒤에야
`FUN_1000d150`으로 변환하는데, 다른 대부분의 `formatCode`는 감지 함수 하나만
쓴다 — 100번이 특별 취급되는 것으로 보아 네이티브 HWP 포맷일 가능성이
있으나(b, 정황 추론), **각 `formatCode`가 실제로 어떤 파일 포맷(HWP/DOC/RTF
등)에 대응하는지는 이번 세션에서 특정하지 못했다(d, 미확인)** — 문자열
테이블이나 리소스에서 명칭 매핑 테이블을 찾지 못했다.

## 5. 서드파티 라이브러리/저작권 고지 종합 (topic 4)

| 컴포넌트 | 위치 | 근거 등급 | 비고 |
|---|---|---|---|
| zlib 1.1.3 / 1.2.3 | `HNCFilter.dll` (정적 링크) | (a) | 카피라이트 문자열 직접 확인, 매우 구버전 |
| zlib 1.2.11 | `HncFilter32.dll`/`HncFilter64.dll` (정적 링크) | (a) | 같은 회사 제품군 내에서도 컴포넌트별 zlib 버전이 다름 |
| minizip (unzip 0.15, Gilles Vollant) | `HncFilter32.dll`/`HncFilter64.dll` | (a)/(c) | 카피라이트 문구는 (a), "minizip 프로젝트 자체"라는 동일성 판단은 (c) |
| Expat XML parser 2.0.1 | `HNCFilter.dll` (정적 링크) | (a) | 구버전, 실제 호출 경로는 미확인 |
| MFC 14.0 (`mfc140u.dll`) | `HMConvDll.dll` (동적 임포트) | (a) | 익스포트 심볼(`CArchive`, `COleStreamFile` 등)로도 교차 확인 |
| MSVC STL / Dinkumware | `HNCFilter.dll` | (a) | `"Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd."` 문자열 — MSVC로 빌드된 C++ 바이너리에 흔한 표준 고지, 특이사항 아님 |
| XmlLite (Windows 내장) | `HncFilter32.dll`/`HncFilter64.dll` (동적 임포트) | (a) | `CreateXmlReader` 임포트로 확인 |

## 6. 남은 열린 질문 (미확인, 다음 세션 과제)

- `HNCFilter.dll`의 `formatCode` ↔ 실제 파일 포맷 매핑표
- HWP 5.x FileHeader 스트림의 실제 파싱 코드(오프셋/필드 단위 검증 여부)
- Expat이 정확히 어느 함수에서 호출되는지의 콜그래프
- `Hwp.exe`의 .NET/JS 계층이 실제로 어떤 특권을 갖고 native 엔진과 통신하는지
  (이번 세션은 .NET 디컴파일러 부재로 확인 불가)
