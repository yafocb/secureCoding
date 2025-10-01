# myapp/forms.py

from django import forms

class idpw(forms.Form):
  id = forms.CharField(max_length=100, label="ID")
  pw = forms.CharField(max_length=200, label="Password")