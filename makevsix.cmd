@ECHO OFF
SETLOCAL ENABLEDELAYEDEXPANSION
REM *******************************************************************************
REM Copyright (C) 2016 Black Duck Software, Inc.
REM http://www.blackducksoftware.com/

REM Licensed to the Apache Software Foundation (ASF) under one
REM or more contributor license agreements. See the NOTICE file
REM distributed with this work for additional information
REM regarding copyright ownership. The ASF licenses this file
REM to you under the Apache License, Version 2.0 (the
REM "License"); you may not use this file except in compliance
REM with the License. You may obtain a copy of the License at

REM http://www.apache.org/licenses/LICENSE-2.0

REM Unless required by applicable law or agreed to in writing,
REM software distributed under the License is distributed on an
REM "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
REM KIND, either express or implied. See the License for the
REM specific language governing permissions and limitations
REM under the License.
REM *******************************************************************************/

CALL npm --version > NUL
IF NOT %ERRORLEVEL%==0 GOTO FAILED

CALL tfx version 1>NUL 2>NUL
IF NOT %ERRORLEVEL%==0 GOTO TFXINSTALL

:NPMINSTALL
ECHO Installing Dependencies...
CALL npm install --only=prod
IF NOT %ERRORLEVEL%==0 GOTO INSTALLFAILED

:CREATEVSIX
ECHO Creating vsix...
CALL tfx extension create --manifest-globs vsts-extension-hub-tfs.json
FOR %%F IN ("*.vsix") DO (
	SET _VSIX=%%F
	set _NEWVSIX=!_VSIX:black-duck-software.=!
	MOVE /y !_VSIX! !_NEWVSIX! >nul
)
IF NOT %ERRORLEVEL%==0 GOTO FAILED

EXIT /B 0

:TFXINSTALL
ECHO Installing tfx-cli...
CALL npm install -g tfx-cli
IF %ERRORLEVEL%==0 GOTO CREATEVSIX

:INSTALLFAILED
ECHO Failed to install npm packages. Ensure Node.js is installed and node and npm are in your path.
EXIT /B %ERRORLEVEL%

:FAILED
ECHO Vsix creation failed
ECHO %ERRORLEVEL%
EXIT /B 1