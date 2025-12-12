# myapp/views.py
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.db import connection
from django.core.files.storage import FileSystemStorage
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from PIL import Image
from .forms import LoginForm, ImageForm, FileUploadForm

import os
import sys
import html
import uuid
import shutil
import base64
import hashlib
import requests
import subprocess




# 메인 선택 화면
def index(request):
    return render(request, 'index.html')

# 1. reflected xss
@csrf_exempt
# reflected XSS 표시 뷰
def rxss(request):
    # POST 요청 처리
    if request.method == 'POST':

        message = request.POST.get('message')

        # message 값을 되돌려주는 처리(safe)
        # 해당 로직이 안전한 처리를 하는 것은 아님.
        if request.POST.get('submit') == 'safe':
            return render(request, 'xss/result.html', {
                'message': message,
                'safe': True
            })

        # message 값을 되돌려주는 처리(vulnerable)
        return render(request, 'xss/result.html', {
            'message': message
        })

    return render(request, 'xss/rxss.html')

# 2. SSRF
# url을 업로드 할 수 있는 url 폼
def image_form(request):
    """
    이미지를 업로드할 폼을 렌더링합니다.
    """
    form = ImageForm()  # image를 url로 업로드 할 수 있는 빈 폼 생성
    return render(request, 'ssrf/image.html', {'form': form})  # 이 폼을 템플릿에 담아서 사용자에게 보여줌


# ssrf에 취약한 뷰 (vulnerable)
@csrf_exempt
def vulnerable_image(request):
    if request.method == 'POST':
        form = ImageForm(request.POST)
        if form.is_valid():  # 데이터 검증
            image_url = form.cleaned_data['image_url']  # 유효성이 검증된 데이터를 가져옴
            result_data = "요청 처리 오류 발생"
            is_image = False
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                response = requests.get(image_url, headers=headers)  # 취약한 쿼리문 / 서버가 직접 사용자가 지정한 url로 http 요청을 보냄
                response.raise_for_status()
                content_type = response.headers.get('Content-Type', '').lower()

                if 'image/' in content_type:
                    # 1. 이미지 처리: Base64 인코딩 및 데이터 URL 생성
                    is_image = True
                    encoded_image = base64.b64encode(response.content).decode('utf-8')
                    result_data = f"data:{content_type};base64,{encoded_image}"

                else:
                    # 2. 텍스트/HTML 처리: 응답 텍스트 노출 (SSRF 시연)
                    result_data = response.text
            except requests.exceptions.RequestException as e:
                result_data = f"요청 실패: {e}"

            return render(request, 'ssrf/vulnerable.html', {
                'result_data': result_data,
                'is_image': is_image
            })  # 결과 반환 공격 성공 시 내부 정보 확인
        return render(request, 'ssrf/image.html', {'form': form})  # 폼 유효성 검사 실패 시, 오류 메시지 담긴 폼을 다시 렌더링
    return render(request, 'ssrf/image.html', {'form': ImageForm()})  # get 요청 시, 비어 있는 새 폼을 렌더링

ALLOW_SERVER_LIST = [
    'https://api.example.com',
    'https://naver.com',
    'https://google.com',
]


# ssrf을 방지하는 안전한 뷰(safe)
@csrf_exempt
def safe_image(request):
    if request.method == 'POST':
        form = ImageForm(request.POST)

        if form.is_valid():
            image_url = form.cleaned_data['image_url']

            if image_url not in ALLOW_SERVER_LIST:  # ssrf 화이트리스트 검사
                error_message = '허용되지 않은 서버입니다'
                return render(request, 'ssrf/safe_result.html', {'result': error_message, 'type': '보안 차단'})  # 오류 메시지 반환

            try:
                response = requests.get(image_url)  # 취약한 쿼리문 / 서버가 직접 사용자가 지정한 url로 http 요청을 보냄
                response_text = response.text
                message_type = "요청 성공"
            except requests.exceptions.RequestException as e:
                response_text = f"요청 실패: {e}"
                message_type = "요청 실패"

            return render(request, 'ssrf/safe_result.html', {'result': response_text, 'type': message_type})  # 요청 결과 반환

        return render(request, 'ssrf/image.html', {'form': form})  # post 요청 폼 유효성 검사 실패 시 오류 메시지 폼 반환

    return render(request, 'ssrf/image.html', {'form': ImageForm()})  # get 요청 시, 비어 있는 새 폼을 렌더링


# 3. 위험한 파일 업로드 (취약 코드 / 안전 코드)
uploaded_files = []
max_size = 10 * 1024 * 1024  # 10MB

# 허용할 이미지 MIME 타입들
ALLOWED_MIME = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/bmp',
    'image/tiff',
]

# 허용할 이미지 확장자들
ALLOWED_EXT = [
    '.jpg', '.jpeg',
    '.png',
    '.gif',
    '.webp',
    '.bmp',
    '.tif', '.tiff',
]

# 확실히 막을 위험 확장자들
DANGEROUS_EXT = {
    '.py': 'python',
    '.sh': 'shell',
    '.bash': 'shell',
    '.php': 'php',
    '.exe': 'exe',
    '.bat': 'bat',
}

# 공통 유틸
def get_file_type(filename):
    """파일 확장자로 파일 형식 감지"""
    ext = os.path.splitext(filename)[1].lower()
    if ext in DANGEROUS_EXT:
        return DANGEROUS_EXT[ext], True  # (파일형식, 실행가능여부)
    return None, False

def get_upload_dir():
    upload_dir = os.path.join(settings.BASE_DIR, 'uploads')
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir

def save_file(upload_dir, uploaded_file, filename=None):
    fs = FileSystemStorage(location=upload_dir)
    if filename:
        saved_name = fs.save(filename, uploaded_file)
    else:
        saved_name = fs.save(uploaded_file.name, uploaded_file)
    file_path = fs.path(saved_name)
    return file_path, saved_name

def verify_image_and_get_size(uploaded_file):
    # Pillow로 이미지 검증 + (width, height) 반환
    uploaded_file.seek(0)
    img = Image.open(uploaded_file)
    img.verify()

    uploaded_file.seek(0)
    img = Image.open(uploaded_file)
    width, height = img.size
    return width, height

def clear_uploaded_files():
    global uploaded_files
    for file_info in uploaded_files:
        file_path = file_info.get('path')
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass
    uploaded_files = []

# 메인 뷰: 취약 / 안전 모드
@csrf_exempt
def file_upload(request):
    # mode = vulnerable : 검증 없이 파일 업로드 (취약 코드)
    # mode = safe       : 확장자 + MIME + 이미지 검증 후 업로드 (안전 코드)
    global uploaded_files
    upload_dir = get_upload_dir()

    if request.method == 'POST':
        # 전체 삭제 버튼
        if request.POST.get('clear'):
            clear_uploaded_files()
            return redirect('file_upload')

        # 파일 실행 (Ajax)
        if request.POST.get('execute'):
            file_index = int(request.POST.get('file_index', -1))
            cmd = request.POST.get('cmd', '').strip()

            if 0 <= file_index < len(uploaded_files):
                file_info = uploaded_files[file_index]
                file_path = file_info.get('path')
                file_type = file_info.get('file_type')

                # 파일 형식별 실행
                try:
                    if file_type == 'python':
                        result = subprocess.run(
                            [sys.executable, file_path, cmd],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        output = result.stdout if result.stdout else result.stderr
                        return JsonResponse({'success': True, 'output': output or '(출력 없음)'})

                    elif file_type == 'shell':
                        result = subprocess.run(
                            ['bash', file_path, cmd],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        output = result.stdout if result.stdout else result.stderr
                        return JsonResponse({'success': True, 'output': output or '(출력 없음)'})

                    elif file_type == 'php':
                        result = subprocess.run(
                            ['php', file_path, cmd],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        output = result.stdout if result.stdout else result.stderr
                        return JsonResponse({'success': True, 'output': output or '(출력 없음)'})

                    elif file_type == 'bat' or file_type == 'exe':
                        return JsonResponse({
                            'success': False,
                            'error': f'{file_type.upper()} 파일은 Linux에서 실행할 수 없습니다.'
                        })

                    else:
                        return JsonResponse({
                            'success': False,
                            'error': f'지원하지 않는 파일 형식입니다: {file_type}'
                        })

                except subprocess.TimeoutExpired:
                    return JsonResponse({'success': False, 'error': '실행 시간 초과 (5초)'})
                except FileNotFoundError as e:
                    return JsonResponse({'success': False, 'error': f'실행 환경 없음: {str(e)}'})
                except Exception as e:
                    return JsonResponse({'success': False, 'error': f'실행 오류: {str(e)}'})

            return JsonResponse({'success': False, 'error': '파일을 찾을 수 없습니다.'})

        form = FileUploadForm(request.POST, request.FILES)

        if not form.is_valid():
            # Form 검증 실패
            return render(request, 'fileUpload/file_upload.html', {
                'form': form,
                'uploaded_files': uploaded_files,
                'error': '파일을 선택해주세요.'
            })

        # Form에서 파일 가져오기
        uploaded_file = form.cleaned_data['upload_file']
        mode = request.POST.get('mode', 'safe')

        if not uploaded_file:
            context = {
                'mode': mode,
                'executed_sql': '업로드할 파일이 없습니다.',
                'results': [],
                'message': '업로드할 파일을 선택해주세요.',
                'attack_success': False,
            }
            return render(request, 'fileUpload/result.html', context)

        filename = uploaded_file.name
        file_ext = os.path.splitext(filename)[1].lower()
        file_size = uploaded_file.size
        content_type = uploaded_file.content_type or '알 수 없음'

        file_type, is_executable = get_file_type(filename)

        # 1) 취약한 코드 (vulnerable)
        if mode == 'vulnerable':
            try:
                file_path, saved_name = save_file(upload_dir, uploaded_file)

                uploaded_files.append({
                    'name': filename,
                    'size': file_size,
                    'mime': content_type,
                    'path': file_path,
                    'mode': 'vulnerable',
                    'file_type': file_type,
                    'is_executable': is_executable,
                })

                executed_sql = (
                    "취약 코드: 확장자, MIME, 내용 검증 없이 파일을 서버에 저장\n"
                    f"저장 경로: {file_path}"
                )

                results = [
                    "🔴 공격 성공! 검증 없이 파일이 업로드되었습니다.",
                    "",
                    f"파일명: {filename}",
                    f"확장자: {file_ext or '(없음)'}",
                    f"MIME 타입: {content_type}",
                    f"크기: {file_size} bytes",
                    f"저장 경로: {file_path}",
                    "",
                    "⚠️ 위험:",
                    "  - 어떤 종류의 파일이든 업로드 가능",
                    "  - 웹셸 / 스크립트 업로드 시 원격 코드 실행 가능",
                ]

                context = {
                    'mode': 'vulnerable',
                    'executed_sql': executed_sql,
                    'results': results,
                    'message': "취약 코드 실행 결과: 공격이 성공했습니다.",
                    'attack_success': True,
                    'error_detail': None,
                }
            except Exception as e:
                context = {
                    'mode': 'vulnerable',
                    'executed_sql': "취약 코드: 파일 저장 중 예외 발생",
                    'results': [],
                    'message': "파일 저장 중 오류가 발생했습니다.",
                    'attack_success': True,  # 로직 자체는 여전히 취약
                    'error_detail': str(e),
                }

            return render(request, 'fileUpload/result.html', context)

        # ───── 2) 안전한 코드 (safe) ─────
        else:
            try:
                # 1) 위험 확장자 바로 차단
                if file_ext in DANGEROUS_EXT:
                    executed_sql = (
                        "안전 코드: 위험 확장자 차단\n"
                        f"차단된 확장자: {file_ext}"
                    )
                    results = [
                        "🛡️ 공격 차단! 위험한 확장자의 파일입니다.",
                        "",
                        f"파일명: {filename}",
                        f"확장자: {file_ext}",
                    ]
                    context = {
                        'mode': 'safe',
                        'executed_sql': executed_sql,
                        'results': results,
                        'message': "안전 코드 실행 결과: 위험 확장자 파일이 차단되었습니다.",
                        'attack_success': False,
                        'error_detail': None,
                    }
                    return render(request, 'fileUpload/result.html', context)

                # 2) 허용 확장자 화이트리스트
                if file_ext not in ALLOWED_EXT:
                    executed_sql = (
                        "안전 코드: 확장자 검증\n"
                        f"업로드된 확장자: {file_ext}\n"
                        f"허용 확장자: {', '.join(ALLOWED_EXT)}"
                    )
                    results = [
                        "🛡️ 공격 차단! 허용되지 않은 확장자의 파일입니다.",
                        "",
                        f"파일명: {filename}",
                        f"확장자: {file_ext or '(없음)'}",
                    ]
                    context = {
                        'mode': 'safe',
                        'executed_sql': executed_sql,
                        'results': results,
                        'message': "안전 코드 실행 결과: 비허용 확장자 파일이 차단되었습니다.",
                        'attack_success': False,
                        'error_detail': None,
                    }
                    return render(request, 'fileUpload/result.html', context)

                # 3) MIME 타입 검증
                if content_type not in ALLOWED_MIME:
                    executed_sql = (
                        "안전 코드: MIME 타입 검증 실패\n"
                        f"업로드된 MIME: {content_type}"
                    )
                    results = [
                        "🛡️ 공격 차단! 허용되지 않은 MIME 타입입니다.",
                        "",
                        f"파일명: {filename}",
                        f"MIME 타입: {content_type}",
                    ]
                    context = {
                        'mode': 'safe',
                        'executed_sql': executed_sql,
                        'results': results,
                        'message': "안전 코드 실행 결과: MIME 검증 단계에서 차단되었습니다.",
                        'attack_success': False,
                        'error_detail': None,
                    }
                    return render(request, 'fileUpload/result.html', context)

                # 4) 크기 검증
                if file_size >= max_size:
                    executed_sql = (
                        "안전 코드: 파일 크기 검증 실패\n"
                        f"파일 크기: {file_size} bytes (최대 {max_size} bytes)"
                    )
                    results = [
                        "🛡️ 공격 차단! 파일 크기 제한을 초과했습니다.",
                        "",
                        f"파일명: {filename}",
                        f"크기: {file_size} bytes",
                    ]
                    context = {
                        'mode': 'safe',
                        'executed_sql': executed_sql,
                        'results': results,
                        'message': "안전 코드 실행 결과: 크기 검증 단계에서 차단되었습니다.",
                        'attack_success': False,
                        'error_detail': None,
                    }
                    return render(request, 'fileUpload/result.html', context)

                # 5) 실제 이미지 파일인지 검증 (Pillow)
                try:
                    width, height = verify_image_and_get_size(uploaded_file)
                    dimensions = f"{width}x{height}"
                except Exception as e:
                    executed_sql = (
                        "안전 코드: 이미지 검증 실패\n"
                        "Pillow로 이미지로 인식되지 않음"
                    )
                    results = [
                        "🛡️ 공격 차단! 실제 이미지 파일이 아닙니다.",
                        "",
                        f"파일명: {filename}",
                        f"확장자: {file_ext}",
                        f"MIME 타입: {content_type}",
                        "",
                        "💡 단순히 확장자만 바꾼 가짜 이미지는 차단됩니다.",
                    ]
                    context = {
                        'mode': 'safe',
                        'executed_sql': executed_sql,
                        'results': results,
                        'message': "안전 코드 실행 결과: 이미지 검증 단계에서 차단되었습니다.",
                        'attack_success': False,
                        'error_detail': f'Pillow 오류: {type(e).__name__}',
                    }
                    return render(request, 'fileUpload/result.html', context)

                # 6) 모든 검증 통과 → 안전하게 저장
                uploaded_file.seek(0)
                file_path, saved_name = save_file(upload_dir, uploaded_file)

                uploaded_files.append({
                    'name': filename,
                    'saved_name': saved_name,
                    'size': file_size,
                    'mime': content_type,
                    'dimensions': dimensions,
                    'path': file_path,
                    'mode': 'safe',
                })

                executed_sql = (
                    "안전 코드: 검증된 이미지 파일만 서버에 저장\n"
                    f"저장 경로: {file_path}"
                )
                results = [
                    "✅ 정상 업로드! 보안 검증을 통과한 이미지 파일입니다.",
                    "",
                    f"파일명: {filename}",
                    f"확장자: {file_ext}",
                    f"MIME 타입: {content_type}",
                    f"크기: {file_size} bytes",
                    f"이미지 크기: {dimensions}",
                    f"저장 경로: {file_path}",
                ]
                context = {
                    'mode': 'safe',
                    'executed_sql': executed_sql,
                    'results': results,
                    'message': "안전 코드 실행 결과: 검증된 이미지 파일만 업로드되었습니다.",
                    'attack_success': False,  # 공격 성공이 아니라 방어 성공
                    'error_detail': None,
                }

            except Exception as e:
                context = {
                    'mode': 'safe',
                    'executed_sql': "안전 코드: 파일 처리 중 예외 발생",
                    'results': [],
                    'message': "파일 처리 중 오류가 발생했습니다.",
                    'attack_success': False,
                    'error_detail': str(e),
                }

            return render(request, 'fileUpload/result.html', context)

    # GET 요청: 업로드 페이지
    form = FileUploadForm()
    return render(request, 'fileUpload/file_upload.html', {
        'form': form,
        'uploaded_files': uploaded_files,
    })
