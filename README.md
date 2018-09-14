# PowerJenkins
PowerJenkins is an PowerShell-based wrapper for the Jenkins API.

To import & use PowerJenkins:
```
Import-Module .\PowerJenkins_v1.psm1
```

Some notes:
This was written in PowerShell 5.1. This was written for how our authentication provider for Jenkins is setup. There is no support for HTTP Basic Authentication- if your Jenkins site is set up this way this will not work for you, though it wouldn't take much to rework for that. OAuth support would be nice too but that is not my use case at this time, so I didn't write for that. I would like to add these later as that becomes more pertinent to my needs but it is not a priority at this time. Right now NGSR (think [CRUD](https://en.wikipedia.org/wiki/Create,_read,_update_and_delete), but using [PowerShell verbiage](https://docs.microsoft.com/en-us/powershell/developer/cmdlet/approved-verbs-for-windows-powershell-commands)) actions are supported against Jenkins jobs. In v2 I would like to add build triggering.
