@echo off
call .venv\Scripts\activate.bat
echo API docs: http://127.0.0.1:8000/docs
uvicorn app.main:app --port 8000
