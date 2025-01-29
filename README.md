# Detection

## Windows Process Creation
### Splunk - Sysmon EventCode 1 (Process Creation)
```
index=critical EventCode=1  
| search CommandLine!="\"C:\\Windows\\System32\\svchost*" 
| search CommandLine!="\"C:\\Windows\\system32\\svchost*" 
| search CommandLine!="\C:\\Windows\\System32\\mousocoreworker.exe"
| search CommandLine!="\"C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunk*" 
| table  _time, ComputerName, ParentUser, CurrentDirectory, CommandLine
```

### What we are filtering out?
- svchost is an executable that contains lots of DLLs. I chose to filter out these events because it causes a lot of noise. Note that there are malware that ulilize this executable and we will detect these separately when we refine our detection.
- splunk is what we are using to monitor our devices
