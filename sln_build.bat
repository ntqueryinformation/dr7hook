@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
msbuild hwbp.sln /nologo /m /v:m /p:Configuration=Debug /p:Platform=x64 || exit /b 1
msbuild hwbp.sln /nologo /m /v:m /p:Configuration=Release /p:Platform=x64 || exit /b 1
echo SLN_BUILD_OK
