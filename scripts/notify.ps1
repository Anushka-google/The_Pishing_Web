param(
    [string]$Title = "Antigravity Alert",
    [string]$Message = "Task completed! Ready for review.",
    [int]$TimeoutSeconds = 8
)

try {
    # 1. Beep audio cue
    [console]::beep(880, 250)
    [console]::beep(1174, 350)
} catch {}

try {
    # 2. Text-to-speech voice ping
    Add-Type -AssemblyName System.Speech -ErrorAction SilentlyContinue
    $speaker = New-Object System.Speech.Synthesis.SpeechSynthesizer
    $speaker.Volume = 100
    $speaker.SpeakAsync($Message) | Out-Null
} catch {}

try {
    # 3. Native Windows Toast notification
    $xmlTemplate = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>$Title</text>
            <text>$Message</text>
        </binding>
    </visual>
</toast>
"@
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
    $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xmlDoc.LoadXml($xmlTemplate)
    $toast = [Windows.UI.Notifications.ToastNotification]::new($xmlDoc)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe").Show($toast)
} catch {}

try {
    # 4. Foreground Popup Box (steals focus and alerts on top of any active window)
    $wshell = New-Object -ComObject Wscript.Shell
    $wshell.Popup($Message, $TimeoutSeconds, $Title, 64) | Out-Null
} catch {}
