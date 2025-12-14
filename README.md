# Django 보안 취약점 테스트 플랫폼 제작

각 취약점에 대해 취약한 코드와 안전한 코드 비교

> ⚠️ **주의**
> 
> 이 프로젝트는 교육 목적으로만 사용해야 함. 실제 서비스에서는 절대로 취약한 코드를 사용 금지. 악용 시 책임은 악용한 당사자에게 있음을 명시합니다.

## 🚀 주요 기능

| 취약점 | 설명 | 학습 내용 |
|-------------------|-------------------------------|-----------|
| **Reflected XSS** | URL 파라미터를 통한 스크립트 삽입 | Django 템플릿의 자동 이스케이프 vs `\|safe` 필터 |
| **SSRF**          | 서버 측 요청 위조               | 화이트리스트 기반 URL 검증 방법 |
| **File Upload**   | 악성 파일 업로드                | 확장자, MIME 타입, 이미지 검증 기법 |

각 테스트는 두 가지 모드를 제공합니다:
- 🔴 **취약 코드**: 보안 검증 없이 동작
- 🟢 **안전 코드**: 적절한 보안 검증 적용

---

## 📁 프로젝트 구조
```
secureCoding/
├── manage.py
├── myproject/
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── myapp/
│   ├── views.py          # 취약점 테스트 로직
│   ├── forms.py          # 폼 정의
│   ├── urls.py           # URL 라우팅
│   ├── templates/
│   │   ├── index.html           # 메인 페이지
│   │   ├── xss/                 # XSS 테스트 템플릿
│   │   ├── ssrf/                # SSRF 테스트 템플릿
│   │   └── fileUpload/          # 파일 업로드 템플릿
│   └── static/
│       └── css/                 # 스타일시트
└── uploads/                     # 업로드된 파일 저장
```

---

## 🛠️ 기술 스택

- **Backend**: Python 3.x, Django 5.2
- **Frontend**: HTML5, CSS3, JavaScript
- **라이브러리**: Pillow (이미지 검증), Requests (HTTP 요청)

---

## 📥 설치 방법

### 1. 저장소 클론

```bash
git clone https://github.com/yafocb/secureCoding.git
cd secureCoding
```

### 2. 가상환경 생성 및 활성화

가상환경 생성
```bash
# 가상환경 생성
python -m venv venv
```

가상환경 활성화
```bash
# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

### 3. 의존성 설치

```bash
pip install django pillow requests
```

---

## ▶️ 실행 방법

```bash
# 개발 서버 실행
python manage.py runserver
```

브라우저에서 접속: **http://127.0.0.1:8000/myapp/**

---

## 🧪 테스트 항목

### 1. Reflected XSS (반사형 크로스 사이트 스크립팅)

**경로**: `/myapp/rxss/`

**테스트 방법**:
```html
<script>alert('XSS')</script>
```

| 모드 | 결과 |
|------|------|
| 취약 코드 | 스크립트가 실행됨 |
| 안전 코드 | 문자열로 이스케이프되어 출력 |

---

### 2. SSRF (서버 측 요청 위조)

**경로**: `/myapp/image/`

**테스트 방법**:
```
# 내부 서버 접근 시도
http://127.0.0.1:8000/admin/
http://localhost/etc/passwd
```

| 모드 | 결과 |
|------|------|
| 취약 코드 | 내부 서버 응답 노출 |
| 안전 코드 | 화이트리스트에 없는 URL 차단 |

**안전 코드의 화이트리스트**:
- `https://api.example.com`
- `https://naver.com`
- `https://google.com`

---

### 3. File Upload (파일 업로드 취약점)

**경로**: `/myapp/file-upload/`

**테스트 방법**:
- `.py`, `.sh`, `.php` 등 실행 가능한 파일 업로드 시도
- 이미지 확장자로 위장한 스크립트 파일 업로드

| 모드 | 결과 |
|------|------|
| 취약 코드 | 모든 파일 업로드 가능 + 실행 버튼 제공 |
| 안전 코드 | 이미지 파일만 허용 (확장자 + MIME + Pillow 검증) |

**안전 코드의 검증 단계**:
1. 위험 확장자 차단 (`.py`, `.sh`, `.php`, `.exe` 등)
2. 허용 확장자 화이트리스트 (`.jpg`, `.png`, `.gif` 등)
3. MIME 타입 검증
4. 파일 크기 제한 (10MB)
5. Pillow를 이용한 실제 이미지 여부 검증

---

## 📚 학습 포인트

### XSS 방어
```python
# Django 템플릿은 기본적으로 자동 이스케이프
{{ message }}          # 안전: HTML 이스케이프됨
{{ message|safe }}     # 취약: 이스케이프 해제
```

### SSRF 방어
```python
ALLOW_SERVER_LIST = ['https://api.example.com', ...]

if image_url not in ALLOW_SERVER_LIST:
    return "허용되지 않은 서버입니다"
```

### 파일 업로드 방어
```python
# 1. 확장자 검증
# 2. MIME 타입 검증
# 3. 실제 파일 내용 검증 (Pillow)
from PIL import Image
img = Image.open(uploaded_file)
img.verify()  # 실제 이미지인지 확인
```

---

## ⚖️ 라이선스

이 프로젝트는 교육 목적으로 제작되었습니다.  
실제 환경에서의 악용은 법적 책임이 따를 수 있음을 다시 한 번 안내합니다.