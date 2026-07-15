@echo off
chcp 65001 >nul
title 网络攻击检测系统
echo ========================================
echo   网络攻击检测系统 (NIDS) v1.0
echo ========================================
echo.
echo   1. 启动 GUI 主界面
echo   2. 启动 GUI + 自动抓包（需管理员+Npcap）
echo   3. 运行模拟演示
echo   4. 运行集成测试
echo   0. 退出
echo.
set /p choice="请输入选项 (0-4): "

if "%choice%"=="1" goto gui
if "%choice%"=="2" goto auto
if "%choice%"=="3" goto demo
if "%choice%"=="4" goto test
if "%choice%"=="0" goto end
echo 无效选项，请重新运行。
pause
goto end

:gui
echo 正在启动 GUI 主界面...
start "" "dist\NetworkAttackDetector.exe"
goto end

:auto
echo 正在启动 GUI + 自动抓包（需要管理员权限）...
python main.py --auto
pause
goto end

:demo
echo 正在运行模拟演示...
python tests\live_demo.py
pause
goto end

:test
echo 正在运行集成测试...
python tests\quick_test.py
pause
goto end

:end
