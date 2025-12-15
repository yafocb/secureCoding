# myapp/views.py
from django.shortcuts import render, redirect
from django.db import connection
from django.http import HttpResponse, FileResponse, JsonResponse
from django.core.files.storage import FileSystemStorage
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from PIL import Image
from .forms import LoginForm, ImageForm

import os, sys, subprocess, uuid, io, re, filetype
import html, shutil, base64, hashlib, requests

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
MAX_SIZE = 10 * 1024 * 1024  # 10MB

# 허용할 이미지 확장자들
ALLOWED_EXT = [
    '.jpg', '.jpeg',
    '.png',
    '.gif',
    '.webp',
    '.bmp',
    '.tif', '.tiff',
]

# 허용할 이미지 MIME 타입들
ALLOWED_MIME = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/bmp',
    'image/tiff',
]

FORMAT_MAP = {
    'JPEG': '.jpg', 
    'PNG': '.png', 
    'GIF': '.gif', 
    'WEBP': '.webp', 
    'BMP': '.bmp', 
    'TIFF': '.tiff'
}

def get_upload_dir():
    upload_dir = os.path.join(settings.BASE_DIR, 'uploads')
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir

def make_result(request, mode, success, steps, filename, **kwargs):
    return render(request, 'fileUpload/result.html', {
        'mode': mode, 'success': success, 'steps': steps, 'filename': filename, **kwargs
    })

@csrf_exempt
def file_upload(request):
    if request.method != 'POST':
        return render(request, 'fileUpload/file_upload.html')
    
    uploaded_file = request.FILES.get('file')
    if not uploaded_file:
        return render(request, 'fileUpload/file_upload.html', {'error': '파일을 선택해주세요.'})
    
    mode = request.POST.get('mode', 'safe')
    filename = uploaded_file.name
    file_ext = os.path.splitext(filename)[1].lower()
    file_size = uploaded_file.size
    upload_dir = get_upload_dir()
    
    # 파일 내용으로 실제 MIME 타입 확인
    uploaded_file.seek(0)
    file_content = uploaded_file.read()
    kind = filetype.guess(file_content)
    real_mime = kind.mime if kind else 'unknown'
    uploaded_file.seek(0)
    
    # 취약 코드
    if mode == 'vulnerable':
        from django.core.files.storage import FileSystemStorage
        fs = FileSystemStorage(location=upload_dir)
        saved_name = fs.save(filename, uploaded_file)
        return make_result(request, 'vulnerable', True, [], filename,
            saved_name=saved_name, file_ext=file_ext, content_type=real_mime,
            file_size=file_size, file_path=fs.path(saved_name),
            file_url=f'/uploads/{saved_name}', logic='검증 없이 모든 파일 저장')
    
    # 안전 코드
    steps = []
    
    # 검증 함수
    def check(step, name, condition, check_msg, allowed_msg, fail_reason, fail_logic):
        steps.append({'step': step, 'name': name, 'check': check_msg, 'allowed': allowed_msg, 'passed': condition})
        if not condition:
            return make_result(request, 'safe', False, steps, filename,
                blocked_step=step, blocked_reason=fail_reason, logic=fail_logic,
                file_ext=file_ext, content_type=real_mime, file_size=file_size)
        return None
    
    # 1~3단계
    if r := check(1, '확장자 검증', file_ext in ALLOWED_EXT, f'확장자: {file_ext}',
        f'허용: {", ".join(ALLOWED_EXT)}', f'허용되지 않은 확장자: {file_ext}', '화이트리스트 기반 확장자 검증'): return r
    if r := check(2, 'MIME 타입 검증 (filetype)', real_mime in ALLOWED_MIME, f'실제 MIME: {real_mime}',
        f'허용: {", ".join(ALLOWED_MIME)}', f'허용되지 않은 MIME 타입: {real_mime}', 'filetype으로 실제 파일 내용 검증'): return r
    if r := check(3, '파일 크기 검증', file_size <= MAX_SIZE, f'크기: {file_size:,} bytes',
        f'최대: {MAX_SIZE:,} bytes', f'파일 크기 초과: {file_size:,} bytes', '파일 크기 제한 검증'): return r
    
    # 4단계: 이미지 검증
    try:
        uploaded_file.seek(0)
        img = Image.open(uploaded_file)
        img.verify()
        uploaded_file.seek(0)
        img = Image.open(uploaded_file)
        width, height, img_format = img.size[0], img.size[1], img.format
        image_valid = True
    except:
        image_valid, width, height = False, 0, 0
    
    if r := check(4, '이미지 검증 (Pillow)', image_valid, 
        f'이미지 크기: {width}x{height}' if image_valid else '이미지 아님',
        '실제 이미지 파일만 허용', '실제 이미지 파일이 아님', 'Pillow 이미지 검증'): return r
    
    # 5단계: 파일명 검증
    safe_filename = re.sub(r'[^a-zA-Z0-9가-힣._-]', '_', filename).replace('..', '_').replace('\x00', '')
    steps.append({'step': 5, 'name': '파일명 검증', 'check': f'원본: {filename}',
        'allowed': '위험 문자 제거', 'passed': True})
    
    # 6단계: 이미지 재생성
    try:
        uploaded_file.seek(0)
        img = Image.open(uploaded_file)
        img_buffer = io.BytesIO()
        if img.mode in ('RGBA', 'P') and img_format == 'JPEG':
            img = img.convert('RGB')
        img.save(img_buffer, format=img_format)
        img_buffer.seek(0)
        regen_ok = True
    except:
        regen_ok = False
    
    if r := check(6, '이미지 재생성 (Polyglot 방지)', regen_ok, f'포맷: {img_format}',
        '이미지 데이터만 추출', '이미지 재생성 실패', '이미지 재생성'): return r
    
    # 저장
    new_ext = FORMAT_MAP.get(img_format, '.png')
    final_name = f"{os.path.splitext(safe_filename)[0]}_{uuid.uuid4().hex[:8]}{new_ext}"
    file_path = os.path.join(upload_dir, final_name)
    with open(file_path, 'wb') as f:
        f.write(img_buffer.getvalue())
    
    return make_result(request, 'safe', True, steps, filename,
        saved_name=final_name, file_ext=new_ext, content_type=real_mime,
        file_size=os.path.getsize(file_path), file_path=file_path,
        file_url=f'/myapp/uploads/{final_name}', image_size=f'{width}x{height}',
        logic='6단계 보안 검증 + 이미지 재생성')

def serve_upload(request, filename):
    file_path = os.path.join(get_upload_dir(), filename)
    return FileResponse(open(file_path, 'rb')) if os.path.exists(file_path) else HttpResponse('파일 없음', status=404)

@csrf_exempt
def execute_file(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST만 허용'})
    
    filename = request.POST.get('filename', '')
    cmd = request.POST.get('cmd', '')
    file_path = os.path.join(get_upload_dir(), filename)
    
    try:
        content = open(file_path, 'rb').read().decode('utf-8', errors='ignore').lower()
    except:
        return JsonResponse({'success': False, 'error': '파일 읽기 실패'})
    
    # 내용으로 타입 판단
    if '<?php' in content: runner = ['php', file_path, cmd]
    elif 'import ' in content or 'def ' in content: runner = [sys.executable, file_path, cmd]
    elif '@echo off' in content: runner = [file_path, cmd]
    elif 'param(' in content: runner = ['powershell', '-File', file_path, cmd]
    else:
        ext = os.path.splitext(filename)[1].lower()
        runners = {'.py': [sys.executable, file_path, cmd], '.php': ['php', file_path, cmd],
                   '.ps1': ['powershell', '-File', file_path, cmd], '.bat': [file_path, cmd], '.exe': [file_path, cmd]}
        runner = runners.get(ext)
        if not runner:
            return JsonResponse({'success': False, 'error': f'실행 불가: {filename}'})
    
    try:
        result = subprocess.run(runner, capture_output=True, text=True, timeout=5)
        return JsonResponse({'success': True, 'output': result.stdout or result.stderr or '(출력 없음)'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})