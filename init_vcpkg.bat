@echo off

if not exist "vcpkg" (
    git clone https://www.github.com/microsoft/vcpkg

    if %ERRORLEVEL% neq 0 (
        exit /b %ERRORLEVEL%
    )

    echo.
    echo VCPKG bootstrap
    echo.

    .\vcpkg\bootstrap-vcpkg.bat
    if %ERRORLEVEL% neq 0 (
        exit /b %ERRORLEVEL%
    )
) else (
    echo VCPKG already exists, skip the installation step
)

echo.
echo Installing dependencies
echo.

set VCPKG_DEFAULT_TRIPLET=x64-windows

.\vcpkg\vcpkg.exe install
if %ERRORLEVEL% neq 0 (
    exit /b %ERRORLEVEL%
)

echo Remember to use the toolchain file with CMAKE:
echo -DCMAKE_TOOLCHAIN_FILE=.\vcpkg\scripts\buildsystems\vcpkg.cmake 

@echo on