# run_fedramp_watch.ps1
# Wrapper for running fedramp_schema_watch.py from Windows Task Scheduler on a
# laptop, alerting by email only (no Jira). Task Scheduler calls this one file.
#
# Setup once:
#   1. Put fedramp_schema_watch.py and this file in the same folder,
#      e.g. C:\Tools\fedramp-watch\
#   2. Edit the values in the CONFIG block below.
#   3. If using Gmail / Google Workspace, create an App Password
#      (Google Account -> Security -> App passwords) and use that as the pass,
#      not your normal password.
#   4. Register the scheduled task with the schtasks line at the bottom.
#
# Security note: this stores the SMTP app password in plaintext in this file.
# For a laptop self-alert that is usually acceptable. To harden, pull the
# password from Windows Credential Manager or a SecureString instead of the
# line below, and keep this file in a user-only readable location.

# ---------------- CONFIG ----------------
$ScriptDir   = "C:\Tools\fedramp-watch"
$PythonExe   = "python"                                  # or full path to python.exe
$StateFile   = "$ScriptDir\watch_state.json"

# SMTP. Gmail / Google Workspace shown; for Office 365 use smtp.office365.com.
$env:FRWATCH_SMTP_HOST = "smtp.gmail.com"
$env:FRWATCH_SMTP_PORT = "587"
$env:FRWATCH_SMTP_USER = "you@yourdomain.com"
$env:FRWATCH_SMTP_PASS = "PUT-APP-PASSWORD-HERE"
$env:FRWATCH_MAIL_FROM = "you@yourdomain.com"
$env:FRWATCH_MAIL_TO   = "you@yourdomain.com"

$env:FRWATCH_STATE     = $StateFile
# Jira intentionally left unset -> Jira alerting stays off.
# ----------------------------------------

Set-Location $ScriptDir
& $PythonExe "$ScriptDir\fedramp_schema_watch.py"
exit $LASTEXITCODE

# ============================================================================
# ONE-TIME TASK REGISTRATION (run this once in an elevated PowerShell, adjust
# the path, then forget about it). Runs daily at 8:00 AM local.
#
#   schtasks /Create /TN "FedRAMP Schema Watch" /SC DAILY /ST 08:00 ^
#     /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Tools\fedramp-watch\run_fedramp_watch.ps1"
#
# To run it on demand for a test:
#   schtasks /Run /TN "FedRAMP Schema Watch"
#
# To remove it:
#   schtasks /Delete /TN "FedRAMP Schema Watch" /F
# ============================================================================
