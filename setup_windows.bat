@echo off
REM One-time setup: virtual env, dependencies, model training, tests
python -m venv .venv || goto :err
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt || goto :err
python train.py || goto :err
python -m pytest
echo.
echo Setup complete. Use run_dashboard.bat or run_api.bat
goto :eof
:err
echo Setup failed. Make sure Python 3.11+ is installed and on PATH.
exit /b 1
