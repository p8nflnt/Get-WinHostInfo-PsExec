# Get-WinHostInfo-PsExec
Retrieve System, Network, Application (Win32Apps & Appx packages), Driver, and Primary user information from hosts - 
even if they may have WinRM, IIS, and PS-Remoting disabled, by means of PsExec.exe of the Sysinternals suite.

# Synopsis:
This project is intended to provide insight into a small environment without more sophisticated management tools in place.

# Warning:
The relaying of commands and gathering of information from Windows hosts is being conducted via PsExec.exe of the Sysinternals suite.
It is important to note that this tool, while not inately malicious, is a component of some malicious tools, and is sometimes used
by threat actors. Thus, it is very likely to trigger false-alerts in a monitored environment. If you run this without getting
prior approval, expect some eyebrow-raises at the minimum.
