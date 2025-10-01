from django.shortcuts import render

from django.shortcuts import render
from .forms import idpw
from .models import Student
from django.db import connection

def index(request):
  if request.method == 'POST':
    form = idpw(request.POST)
    if form.is_valid():
      userID = form.cleaned_data['id']
      password = form.cleaned_data['pw']

      # mode check (vulnerable/safe)
      mode = request.POST.get('mode')  # vulnerable or safe

      results = []
      executed_sql = ""
      params = None
      message = ""

      if mode == 'vulnerable':
        # Vulnerable Code: User's input을 직접 f-string에 넣음
        executed_sql = f"SELECT id, userID, password FROM myapp_student WHERE userID = '{userID}' AND password = '{password}'"
        with connection.cursor() as curs:
          try:
            curs.execute(executed_sql)
            results = curs.fetchall()
          except Exception as e:
            message = str(e)

      else:
        # Safe Code: Use Prameter binding
        executed_sql = "SELECT id, userID, password FROM myapp_student WHERE userID = %s AND password = %s"
        params = [userID, password]
        with connection.cursor() as curs:
          try:
            curs.execute(executed_sql, params)
            results = curs.fetchall()
          except Exception as e:
            message = str(e)

      return render(request, 'success.html', {
        'form': form,
        'mode': mode,
        'executed_sql': executed_sql,
        'params': params,
        'results': results,
        'message': message,
        'user_id': userID,
        'pw': password
      })

  else:
    form = idpw()

  return render(request, 'index.html', {'form': form})

def student_list(request):
  students = Student.objects.all()
  return render(request, 'list.html', {'students': students})