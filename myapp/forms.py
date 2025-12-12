# myapp/forms.py

from django import forms

# 로그인 테스트 뷰에서 사용하는 로그인 폼
#    - views.py의 login_form, vulnerable_login 등에서 사용됨

class LoginForm(forms.Form):
    # Auth 모델의 user_id에 대응하는 필드
    user_id = forms.CharField(
        label='ID',
        max_length=50,
        widget=forms.TextInput(attrs={'placeholder': 'ID를 입력하세요'})
    )
    # Auth 모델의 password에 대응하는 필드
    password = forms.CharField(
        label='Password',
        max_length=50,
        widget=forms.PasswordInput(attrs={'placeholder': 'Password를 입력하세요'})
    )

class ImageForm(forms.Form):
    image_url = forms.URLField(
        label='이미지 URL',
        max_length=500,
        required=True,
        widget=forms.TextInput(attrs={'placeholder': '예: https://example.com/image.jpg'})
    )


# 파일 업로드 폼
class FileUploadForm(forms.Form):
    upload_file = forms.FileField(
        label='업로드할 파일 선택',
        required=True,
        widget=forms.FileInput(attrs={
            'id': 'upload_file',
            'class': 'file-input',
        })
    )
















