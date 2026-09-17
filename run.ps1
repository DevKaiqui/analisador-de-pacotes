param(
    [string]$Interface = "",
    [int]$MaxPackets = 200,
    [int]$DurationSeconds = 60,
    [string]$Filter = "ip or arp",
    [switch]$Promiscuous,
    [switch]$ShowSensitive,
    [switch]$List
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$maven = Get-Command mvn -ErrorAction SilentlyContinue
$javac = Get-Command javac -ErrorAction SilentlyContinue

if (-not $javac) {
    $intellijHome = Get-ChildItem (Join-Path $env:LOCALAPPDATA "Programs") -Directory -Filter "IntelliJ IDEA*" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    $intellijJdk = if ($intellijHome) { Join-Path $intellijHome.FullName "jbr" } else { "" }
    if (Test-Path (Join-Path $intellijJdk "bin\javac.exe")) {
        $env:JAVA_HOME = $intellijJdk
        $env:PATH = (Join-Path $intellijJdk "bin") + ";" + $env:PATH
    }
}

if ($maven) {
    $mavenCommand = $maven.Source
} else {
    $intellijHome = Get-ChildItem (Join-Path $env:LOCALAPPDATA "Programs") -Directory -Filter "IntelliJ IDEA*" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    $intellijMaven = if ($intellijHome) { Join-Path $intellijHome.FullName "plugins\maven\lib\maven3\bin\mvn.cmd" } else { "" }
    if (-not (Test-Path $intellijMaven)) {
        throw "Maven nao encontrado. Instale o Maven ou adicione mvn ao PATH."
    }
    $mavenCommand = $intellijMaven
}

Push-Location $projectRoot
try {
    & $mavenCommand -q test
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $dependencies = @(
        "$env:USERPROFILE\.m2\repository\org\pcap4j\pcap4j-core\1.8.2\pcap4j-core-1.8.2.jar",
        "$env:USERPROFILE\.m2\repository\org\pcap4j\pcap4j-packetfactory-static\1.8.2\pcap4j-packetfactory-static-1.8.2.jar",
        "$env:USERPROFILE\.m2\repository\net\java\dev\jna\jna\5.14.0\jna-5.14.0.jar",
        "$env:USERPROFILE\.m2\repository\net\java\dev\jna\jna-platform\5.14.0\jna-platform-5.14.0.jar",
        "$env:USERPROFILE\.m2\repository\org\slf4j\slf4j-api\2.0.13\slf4j-api-2.0.13.jar",
        "$env:USERPROFILE\.m2\repository\org\slf4j\slf4j-simple\2.0.13\slf4j-simple-2.0.13.jar"
    )

    foreach ($dependency in $dependencies) {
        if (-not (Test-Path $dependency)) {
            throw "Dependencia nao encontrada: $dependency"
        }
    }

    $classpath = @("target\classes") + $dependencies
    $javaArgs = @(
        "-Djna.library.path=C:\Windows\System32\Npcap",
        "-Dorg.slf4j.simpleLogger.defaultLogLevel=error",
        "-cp",
        ($classpath -join ";"),
        "Main"
    )

    if ($List) {
        $javaArgs += "--list"
    }

    if ($Interface.Trim().Length -gt 0) {
        $javaArgs += @("--interface", $Interface)
    }

    $javaArgs += @("--max-packets", $MaxPackets.ToString())
    $javaArgs += @("--duration-seconds", $DurationSeconds.ToString())
    $javaArgs += @("--filter", $Filter)

    if ($Promiscuous) {
        $javaArgs += "--promiscuous"
    }

    if ($ShowSensitive) {
        $javaArgs += "--show-sensitive"
    }

    & java @javaArgs
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}
