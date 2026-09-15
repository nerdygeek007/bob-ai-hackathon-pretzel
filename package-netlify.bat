@echo off
echo ========================================================
echo Building Sentinel-X Production Bundle for Netlify...
echo ========================================================
cd /d "%~dp0src"
call npm run build
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed!
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo Packaging files into sentinel-x-ui-netlify.zip (POSIX compliant)...
cd /d "%~dp0"
if exist sentinel-x-ui-netlify.zip del sentinel-x-ui-netlify.zip
tar -a -c -f sentinel-x-ui-netlify.zip -C src/dist assets favicon.svg icons.svg index.html _redirects

echo.
echo ========================================================
echo [SUCCESS] Netlify package ready!
echo Output: %~dp0sentinel-x-ui-netlify.zip
echo.
echo TO HOST ON NETLIFY:
echo 1. Open https://app.netlify.com/drop in your browser
echo 2. Drag and drop 'sentinel-x-ui-netlify.zip' onto the page
echo 3. Netlify will deploy your live site immediately!
echo ========================================================
