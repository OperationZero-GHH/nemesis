# Nemesis Toolkit PowerShell Launcher
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& python "$scriptDir\nemesis.py" @args
