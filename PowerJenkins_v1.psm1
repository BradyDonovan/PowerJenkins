function Get-PowerJenkinsConfigFile {
    <#
    .SYNOPSIS
    Retrieves the PowerJenkins config file path.
    
    .DESCRIPTION
    Joins the LOCALAPPDATA varible together with child path to encapsulate the final resting place of the config file.
    
    .EXAMPLE
    $pathToConfigFile = Get-PowerJenkinsConfigFile
    
    .NOTES
    Contact information:
    https://github.com/BradyDonovan/
    #>
    process {
        Join-Path -Path $env:LOCALAPPDATA -ChildPath \PowerJenkins\config.xml
    }
}

Function Set-PowerJenkinsModuleConfig {
    <#
    .SYNOPSIS
    Sets the PowerJenkins module config file.
    
    .DESCRIPTION
    Calls Set-DefaultJenkinsServer which then drops the config.xml to appdata after testing whether or not the PowerJenkins appdata directory exists.
    
    .EXAMPLE
    Set-PowerJenkinsModuleConfig -ComputerName 'https://theCoolestJenkinsServerInTown:8080/'

    .NOTES
    Contact information:
    https://github.com/BradyDonovan/
    #>
    [Cmdletbinding()]
    param(
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "Provide a computer name to test for the presence of a Jenkins server, and if valid, set as the default.")]
        [alias("address")]
        [alias("ipAddress")]
        [alias("jenkinsIPAddress")]
        [string]$ComputerName
    )

    process {
        IF ((Test-Path -Path (Join-Path -Path $env:LOCALAPPDATA -ChildPath \PowerJenkins\)) -eq $false) {
            Try {
                New-Item -Path (Join-Path -Path $env:LOCALAPPDATA -ChildPath \PowerJenkins\) -ItemType Directory | Out-Null
            }
            Catch {
                throw "Could not create PowerJenkins config directory in %localappdata%\PowerJenkins. Check permissions on this directory."
            }
        }

        $server = Confirm-JenkinsServer -ComputerName $ComputerName
        IF (($server.Valid -eq $true) -and ($server.ServerInformation.hudson)) {
            Set-DefaultJenkinsServer -JenkinsSystemName $server.ServerInformation.hudson.url
        }
    }
}

function Set-DefaultJenkinsServer {
    <#
    .SYNOPSIS
    Sets the default Jenkins server.
    
    .DESCRIPTION
    This will actually do the XML export of what is specified from Set-PowerJenkinsModuleConfig. Works by URI parsing the input and then setting on the .AbsoluteUri property. I would advise against using this standalone.
    This is integrated into Set-PowerJenkinsModuleConfig, which has a check to actually confirm the specified Jenkins server (Confirm-JenkinsServer) and then set it based off confirmation.
    
    .EXAMPLE
    Set-DefaultJenkinsServer -JenkinsSystemName 'https://theCoolestJenkinsServerInTown:8080/'

    .NOTES
    Contact information:
    https://github.com/BradyDonovan/
    #>
    [Cmdletbinding()]
    param (
        [alias("ServerName")]
        [alias("Server")]
        [alias("System")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $false, HelpMessage = "Enter the JenkinsSystemName of the Jenkins server in the following format: https://pathToServer/")]
        [ValidateNotNullOrEmpty()]
        [URI]$JenkinsSystemName
    )

    process {
        $JenkinsSystemNameDefault = $JenkinsSystemName.AbsoluteUri
        $JenkinsSystemNameDefault | Export-CliXml (Get-PowerJenkinsConfigFile)
    }
}

function Get-DefaultJenkinsServer {
    <#
    .SYNOPSIS
    Retrieves the value stored within the config.xml file.
    
    .DESCRIPTION
    Retrieves the value stored within the config.xml file.
    
    .EXAMPLE
    $defaultServer = Get-DefaultJenkinsServer

    .NOTES
    Contact information:
    https://github.com/BradyDonovan/
    #>
    (Import-Clixml (Get-PowerJenkinsConfigFile))
}

function Confirm-JenkinsServer {
    <#
    .SYNOPSIS
    Confirms the presence of a Jenkins server.
    
    .DESCRIPTION
    Send an empty UDP datagram to the specified target IP and parse the reply to ensure the target is indeed a Jenkins server.
    
    .EXAMPLE
    Confirm-JenkinsServer -ComputerName $ipAddress

    .INPUTS
    Specify the IP address of the Jenkins server in question. Pipeline input is accepted.

    .OUTPUTS
    If valid, Confirm-JenkinsServer will return a Hashtable containing the 'Valid = $true' property and ServerInformation property. If invalid, Confirm-JenkinsServer will return False.
    
    .NOTES
    The idea is that you will work this into your logins to ensure that you are actually sending HTTP POSTs to the right resource.

    See the following for details:
        http://kohsuke.org/2010/05/14/auto-discovering-hudson-in-the-network/
        https://wiki.jenkins.io/display/JENKINS/Auto-discovering+Jenkins+on+the+network

    Contact information:
    https://github.com/BradyDonovan/
    #>
    [Cmdletbinding()]
    param(
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "Provide a computer name to test for the presence of a Jenkins server.")]
        [alias("address")]
        [alias("ipAddress")]
        [alias("jenkinsIPAddress")]
        [string]$ComputerName
    )
    process {
        #^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$ <-- IP Address matching RegEx
        IF ($ComputerName -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
            #ingest IP address, create IP object
            $inputIPAddress = [System.Net.IPAddress]::Parse($ComputerName)

            #build ipEndpoint obj for $udpConnection.Receive
            $endpointObj = New-Object System.Net.IPEndPoint($inputIPAddress, 33848)
        }
        ELSE {
            #Trim the port # if it's there
            IF ($ComputerName -match '([:](\d+))') {
                $ComputerName = $ComputerName -replace '([:](\d+))'
            }
            #Trim http(s) if it's there
            IF ($ComputerName -match '^https?://') {
                $ComputerName = $ComputerName -replace '^https?://'
            }

            #assume it's a hostname
            $inputIPAddress = [System.Net.Dns]::GetHostAddresses($ComputerName)

            #build ipEndpoint obj for $udpConnection.Receive
            $endpointObj = New-Object System.Net.IPEndPoint($inputIPAddress[0], 33848)
        }
        
        #create UDP Client
        $udpConnection = New-Object System.Net.Sockets.UdpClient
        $udpConnection.client.ReceiveTimeout = 10000
        $udpConnection.Client.SendTimeout = 10000
                
        #per specification, a UDP Datagram needs to be sent (https://wiki.jenkins.io/display/JENKINS/Auto-discovering+Jenkins+on+the+network)
        $sendByte = [System.Text.Encoding]::ASCII.GetBytes('Hey Jenkins, are you there?')
        
        #send (https://msdn.microsoft.com/en-us/library/82dxxas0(v=vs.110).aspx)
        $udpConnection.Send($sendByte, 0, $endpointObj)>$null
        
        #receive bytes
        Try {
            $receiveBytes = $udpConnection.Receive([ref]$endpointObj)
            [xml]$replyString = [System.Text.Encoding]::ASCII.GetString($receiveBytes)
            IF ($replyString) {
                Return @{ 
                    Valid             = $true
                    ServerInformation = $replyString
                }
            }
        }
        Catch {
            IF ($null -eq $receiveBytes) {
                Return $false
            }
        }
    }
}

function Invoke-JenkinsLogin {
    <#
    .SYNOPSIS
    Pass Jenkins login by POSTing credentials to the j_acegi_security_check resource.

    .DESCRIPTION
    Fill $postParams with needed credential items to pass Jenkins auth and get a session cookie in return.

    .OUTPUTS
    A [Microsoft.PowerShell.Commands.WebRequestSession] object is returned to be used in successive requests.

    .EXAMPLE
    $sessionCookie = Invoke-JenkinsLogin

    .NOTES

    #>
    [CmdletBinding()]
    Param ()
    process {
        #Configuration file check
        Try {
            #Gather default JenkinsSystemName from config file
            $JenkinsSystemName = Get-DefaultJenkinsServer
        }
        Catch {
            throw "Looks like you haven't run the setup. Please run Set-PowerJenkinsModuleConfig to continue."
        }

        #set TLS version appropriate to Jenkins
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

        #define POST point & build params
        $formActionUri = "$JenkinsSystemName/j_acegi_security_check"
        $cred = Get-Credential
        $ptCred = $cred.GetNetworkCredential().Password
        $postParams = @{
            'j_username' = "$($cred.UserName)";
            'j_password' = "$ptCred";
            'from'       = "/";
        }

        #send the login POST
        Try {
            $loginRequest = Invoke-WebRequest -Uri $formActionUri -Method Post -Body $postParams -SessionVariable sessionVar
        }
        Catch {
            Write-Error "Login failure. Reason: $_"
        }

        #form new websession & give it our session cookie.
        $loginCookies = $sessionVar.Cookies.GetCookies($formActionUri)
        $newWebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $newWebSession.Cookies.Add($loginCookies)   

        #sent it out for the function
        return $newWebSession
    }
}

function Get-JenkinsCrumb {
    <#
    .SYNOPSIS
    Gather a Jenkins crumb to use with successive API calls to Jenkins.

    .DESCRIPTION
    GET to $JenkinsSystemName/crumbIssuer/api/json so you can retrieve a Jenkins crumb for successive API calls to Jenkins. Comes in JSON format. Is then parsed for the value of 'crumb' and returned at the end of the function.

    .PARAMETER webRequestSessionCookie
    Specifies the WebRequestSession object.

    .PARAMETER SessionCookie
    Alias for webRequestSessionCookie.

    .INPUTS
    Piping to Get-JenkinsCrumb is supported.

    .OUTPUTS
    A Jenkins crumb- basically a CRSF token.

    .EXAMPLE
    Get-JenkinsCrumb -SessionCookie (Invoke-JenkinsLogin)

    .EXAMPLE
    $sessionCookie = Invoke-JenkinsLogin
    Get-JenkinsCrumb -webRequestSessionCookie $sessionCookie

    .NOTES
    Use this in tandem with Invoke-JenkinsLogin to fetch a crumb from Jenkins.
    See https://support.cloudbees.com/hc/en-us/articles/219257077-CSRF-Protection-Explained for further reading on why this is needed.

    '-SessionCookie' is a supported alias for the '-webRequestSessionCookie' parameter.

    Contact information:
    https://github.com/BradyDonovan/
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Provide a WebRequestSession object that contains a session cookie from passing Jenkins login.")]
        [alias("SessionCookie")]
        [ValidateScript( {
                ($_.Cookies.Count -eq 1) -and (($_.Cookies.GetCookieHeader((Get-DefaultJenkinsServer))) -like "*JSESSIONID.*" )
                #throw "Incorrect values supplied. This session cookie will not work. Please run Invoke-JenkinsLogin again."
                #Not ready to implement throws in the ValidateScript yet but this is definitely an extra step and isn't necessary for operation
            } ) ]
        [Microsoft.PowerShell.Commands.WebRequestSession]$webRequestSessionCookie
    )
    process {
        #Configuration file check
        Try {
            #Gather default JenkinsSystemName from config file
            $JenkinsSystemName = Get-DefaultJenkinsServer
        }
        Catch {
            throw "Looks like you haven't run the setup. Please run Set-PowerJenkinsModuleConfig to continue."
        }

        $crumbParams = @{
            Uri         = "$JenkinsSystemName/crumbIssuer/api/json"
            Method      = 'GET'
            ContentType = 'application/json'
            WebSession  = $webRequestSessionCookie
        }
        $crumbReturn = Invoke-RestMethod @crumbParams
        Return @{ $crumbReturn.crumbRequestField = $crumbReturn.crumb }
    }
}

function Confirm-JenkinsCrumb {
    <#
    .SYNOPSIS
    Confirm that a JenkinsCrumb is valid.

    .DESCRIPTION
    POST a Jenkins crumb to "$JenkinsSystemName/whoAmI/api/json", on the premise that a Jenkins CSRF token (crumb) is validated for every POST to a resource in the Jenkins site.

    .EXAMPLE
    $sessionCookie = Invoke-JenkinsLogin
    $crumb = Get-JenkinsCrumb -webRequestSessionCookie $sessionCookie
    Confirm-JenkinsCrumb -crumb $crumb -webRequestSessionCookie $sessionCookie

    .EXAMPLE
    $crumb = Get-JenkinsCrumb -SessionCookie (Invoke-JenkinsLogin)
    Confirm-JenkinsCrumb -jenkinsCrumb $crumb -webRequestSessionCookie $sessionCookie

    .INPUTS
    Confirm-JenkinsCrumb will take pipeline input of a [System.Collections.Hashtable] object containing the crumb / token itself, and also input for a session cookie to authenticate the POST.

    .OUTPUTS
    True if the Jenkins crumb is valid. False if it is invalid.

    .NOTES
    As shown in the examples, use this with Get-JenkinsCrumb to confirm the validity of a crumb.

    Contact information:
    https://github.com/BradyDonovan/
    #>

    [Cmdletbinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Provide a System.Collections.Hashtable object from the return of Get-JenkinsCrumb to confirm that the crumb is valid.")]
        [alias("crsfToken")]
        [alias("jenkinsCrumb")]
        [ValidateScript( { ($_.'Jenkins-Crumb'.Length -eq 32) } ) ] #they always seem to be 32 chars in length. I can't think of any better input validation that this. Suggestions are welcome.
        [System.Collections.Hashtable]$crumb,
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Provide a WebRequestSession object that contains a session cookie from passing Jenkins login.")]
        [alias("SessionCookie")]
        [ValidateScript( {
                ($_.Cookies.Count -eq 1) -and (($_.Cookies.GetCookieHeader((Get-DefaultJenkinsServer))) -like "*JSESSIONID.*" )
                #throw "Incorrect values supplied. This session cookie will not work. Please run Invoke-JenkinsLogin again."
                #Not ready to implement throws in the ValidateScript yet but this is definitely an extra step and isn't necessary for operation
            } ) ]
        [Microsoft.PowerShell.Commands.WebRequestSession]$webRequestSessionCookie
    )
    process {
        #Configuration file check
        Try {
            #Gather default JenkinsSystemName from config file
            $JenkinsSystemName = Get-DefaultJenkinsServer
        }
        Catch {
            throw "Looks like you haven't run the setup. Please run Set-PowerJenkinsModuleConfig to continue."
        }

        $crumbParams = @{
            Uri    = "$JenkinsSystemName/whoAmI/api/json"
            Method = 'Post'
        }
        try {
            Invoke-RestMethod @crumbParams > $null
        }
        catch {
            $crumbReturnStatusCode = $_.Exception.Response.StatusCode.value__
        }
        IF ($crumbReturnStatusCode) {
            Return $false
        }
        ELSE {
            Return $true
        }
    }
}


function New-JenkinsJob {
    <#
    .SYNOPSIS
    Create a new Jenkins job.
    
    .DESCRIPTION
    From a name and repository, clone the template job and modify the Url node containing the URI to the Git repo with a supplied URI. Change it, then POST it back to Jenkins to create a new job.
    
    .PARAMETER Repository
    Specifies a URI to a .git repository.
    
    .PARAMETER Name
    Specifies the name of the Jenkins job.

    .EXAMPLE
    New-JenkinsJob -TemplateJob /job/GroupName/JobName/config.xml -Repository 'https://path/to/repo.git' -Name 'Test_Job12345' -Group 'PowerShellAllTheThings'
    
    .NOTES
    Contact information:
    https://github.com/BradyDonovan/
    #>

    [Cmdletbinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $false, HelpMessage = "Provide a path to the config.xml you would like to base your job off of.", ValueFromPipelineByPropertyName = $true)]
        [ValidateScript ( { 
                ($_.Substring($_.Length - 4) -eq '.xml')
            })]
        [alias("JobToClone")]
        [string]$TemplateJob,
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $false, HelpMessage = "Provide the location of a repository to point Jenkins at.", ValueFromPipelineByPropertyName = $true)]
        [alias("Project")]
        [alias("Repo")]
        [alias("GitLocation")]
        [ValidateScript ( {
                (($_.OriginalString.Substring($_.OriginalString.Length - 4)) -eq '.git') -and (($_.AbsoluteUri.Substring($_.AbsoluteUri.Length - 4)) -eq '.git')
            } )
        ]
        [URI]$Repository,
        [Parameter(Position = 2, Mandatory = $true, ValueFromPipeline = $false, HelpMessage = "Provide the name of the new job.", ValueFromPipelineByPropertyName = $true)]
        [alias("NewJobName")]
        [alias("NewJenkinsJobName")]
        [string]$Name,
        [Parameter(Mandatory = $false, HelpMessage = 'Enter a Group / Folder name if your job isn''t at the root level.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Group
    )
    process {
        #Configuration file check
        Try {
            #Gather default JenkinsSystemName from config file
            $JenkinsSystemName = Get-DefaultJenkinsServer
        }
        Catch {
            throw "Looks like you haven't run the setup. Please run Set-PowerJenkinsModuleConfig to continue."
        }

        Try {
            $templateURL = "/$TemplateJob"
            $targetRepository = "$($Repository.AbsoluteUri)" #https://path/to/repo.git

            #get Template job, change url to target repo
            $irmSplat = @{
                Method      = 'GET'
                Uri         = $templateURL
                ContentType = 'application/xml'
            }
            [xml]$jenkinsTemplateJobXML = Invoke-JenkinsRestMethod @irmSplat
            $xmlGitUrlConfigLocation = $jenkinsTemplateJobXML.SelectSingleNode("descendant::definition/scm/userRemoteConfigs/hudson.plugins.git.UserRemoteConfig/url")
            $xmlGitUrlConfigLocation.InnerText = $targetRepository
        }
        Catch {
            "Something failed. Reason: $_"
        }
        Try {
            #was a Group specified?
            IF ($Group) {
                $newJobName = "$Name"
                $jenkinsPostUrl = "/job/$Group/createItem?name=$newjobName"
                $irmSplat = @{
                    Method      = 'POST'
                    Uri         = $jenkinsPostUrl
                    ContentType = 'application/xml'
                    Body        = $jenkinsTemplateJobXML.InnerXml
                }
            }
            #if not, continue as normal
            ELSE {
                $newJobName = "$Name"
                $jenkinsPostUrl = "/createItem?name=$newjobName"
                $irmSplat = @{
                    Method      = 'POST'
                    Uri         = $jenkinsPostUrl
                    ContentType = 'application/xml'
                    Body        = $jenkinsTemplateJobXML.InnerXml
                }
            }
            Invoke-JenkinsRestMethod @irmSplat
        }
        Catch {
            "Something failed. Reason: $_"
        }
    }
}

function Get-JenkinsJob {
    <#
    .SYNOPSIS
    Get the details for a Jenkins job.
    
    .DESCRIPTION
    Specify a Job name and Group name if applicable and a HTTP GET will be sent to /api/json?jobs.
    
    .PARAMETER Job
    Specify the name of the Job you would like to get.
    
    .PARAMETER Group
    Specify the name of the Group or Folder if your job isn't at the root level.

    .EXAMPLE
    Get-JenkinsJob -Name 'Test_Job12345' -Group 'PowerShellAllTheThings'
    
    .NOTES
    Contact information:
    https://github.com/BradyDonovan/
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Enter the name of a Jenkins Job.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [Alias("Name", "JobName")]
        [string]$Job,
        [Parameter(Mandatory = $false, HelpMessage = 'Enter a Group / Folder name if your job isn''t at the root level.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Group
    )
    process {
        #Configuration file check
        Try {
            #Gather default JenkinsSystemName from config file
            $JenkinsSystemName = Get-DefaultJenkinsServer
        }
        Catch {
            throw "Looks like you haven't run the setup. Please run Set-PowerJenkinsModuleConfig to continue."
        }

        #was a Group specified?
        IF ($Group) {
            $JobResponse = Invoke-JenkinsRestMethod -Method GET -Uri "job/$Group/job/$Job/api/json?jobs"
        }
        #if not, continue as normal
        ELSE {
            $JobResponse = Invoke-JenkinsRestMethod -Method GET -Uri "job/$Job/api/json?jobs" 
        }
        Return $JobResponse
    }
}
function Set-JenkinsJob {
    <#
    .SYNOPSIS
    Updates a Jenkins job.
    
    .DESCRIPTION
    Use this command to update a Jenkins job with a specified config.xml file. This will not create jobs if they do not already exist; please use New-Jenkins job for this.
    
    .PARAMETER Job
    Specify the name of the job you would like to update
    
    .PARAMETER Group
    Specify the name of the Group or Folder if your job isn't at the root level.

    .PARAMETER ConfigXML
    Provide the config.xml you want to update the Jenkins job with. I recommend grabbing this ahead of time and storing it into a variable rather than squeezing it into the parameter.

    .EXAMPLE
    [xml]$configXML = Get-Content C:\path\to\config.xml
    Set-JenkinsJob -Name 'Test_Job12345' -Group 'PowerShellAllTheThings' -ConfigXML $configXML
    
    .NOTES
    Contact information:
    https://github.com/BradyDonovan/
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Enter the name of a Jenkins Job.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [Alias("Name", "JobName")]
        [string]$Job,
        [Parameter(Mandatory = $false, HelpMessage = 'Enter a Group / Folder name if your job isn''t at the root level.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Group,
        [Parameter(Mandatory = $false, HelpMessage = 'Specify what config file you would like to use to update the job. Need to be in XML form.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [xml]$ConfigXML
    )
    process {
        #Configuration file check
        Try {
            #Gather default JenkinsSystemName from config file
            $JenkinsSystemName = Get-DefaultJenkinsServer
        }
        Catch {
            throw "Looks like you haven't run the setup. Please run Set-PowerJenkinsModuleConfig to continue."
        }

        Try {
            #was a Group specified?
            IF ($Group) {
                $JobName = "$Name"
                $jenkinsPOSTUrl = "/job/$Group/$jobName/config.xml"
                $irmSplat = @{
                    Method      = 'POST'
                    Uri         = $jenkinsPOSTUrl
                    ContentType = 'application/xml'
                    Body        = $ConfigXML
                }
            }
            #if not, continue as normal
            ELSE {
                $JobName = "$Name"
                $jenkinsPOSTUrl = "/$jobName/config.xml"
                $irmSplat = @{
                    Method      = 'POST'
                    Uri         = $jenkinsPOSTUrl
                    ContentType = 'application/xml'
                    Body        = $ConfigXML
                }
            }
            Invoke-JenkinsRestMethod @irmSplat
        }
        Catch {
            "Something failed. Reason: $_"
        }
    }
}

function Remove-JenkinsJob {
    <#
    .SYNOPSIS
    Remove a Jenkins job.
    
    .DESCRIPTION
    Specify a Job name and Group name if applicable and a HTTP POST will be sent to job/$Job/doDelete.
    
    .PARAMETER Job
    Specify the name of the Job you would like to remove.
    
    .PARAMETER Group
    Specify the name of the Group or Folder if your job isn't at the root level.

    .EXAMPLE
    Remove-JenkinsJob -Name 'Test_Job12345' -Group 'PowerShellAllTheThings'
    
    .NOTES
    Contact information:
    https://github.com/BradyDonovan/
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Enter the name of a Jenkins Job.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [Alias("Name", "JobName")]
        [string]$Job,
        [Parameter(Mandatory = $false, HelpMessage = 'Enter a Group / Folder name if your job isn''t at the root level.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Group
    )
    process {
        #Configuration file check
        Try {
            #Gather default JenkinsSystemName from config file
            $JenkinsSystemName = Get-DefaultJenkinsServer
        }
        Catch {
            throw "Looks like you haven't run the setup. Please run Set-PowerJenkinsModuleConfig to continue."
        }

        #was a Group specified?
        IF ($Group) {
            Invoke-JenkinsRestMethod -Method POST -Uri "job/$Group/job/$Job/doDelete"
        }
        #if not, continue as normal
        ELSE {
            Invoke-JenkinsRestMethod -Method POST -Uri "job/$Job/doDelete" 
        }
    }
}

Function Invoke-JenkinsRestMethod {
    <#
    .SYNOPSIS
    Essentially Invoke-RestMethod, but handles the authentication depending on usage context.
    
    .DESCRIPTION
    This function serves as a wrapper for Invoke-RestMethod, except it handles cookie based authentication and retrieving CSRF tokens (crumbs) depending on usage context.
    You should not be using this function by itself as the New/Get/Set/Remove-JenkinsJobs cmdlets are designed to work with this function so you don't have to.
    
    .PARAMETER Method
    Enter the web request method needed. In my experience so far I have only encountered GET & POST.
    
    .PARAMETER Uri
    Enter the URI of the resource you are targeting.

    .PARAMETER Body
    Provide a Body for the web request if needed.

    .PARAMETER Headers
    Specify request headers if needed. Our CSRF token (crumb) goes here.

    .PARAMETER ContentType
    Specify a Content-Type being sent in your POST. Creating a Jenkins Job, for example, requires 'application/xml' to be set for the Content-Type.

    .EXAMPLE
    The below example is the usage of Invoke-JenkinsRestMethod in Remove-JenkinsJob.

    Invoke-JenkinsRestMethod -Method POST -Uri "job/$Job/doDelete"

    See New/Get/Set-JenkinsJob for more examples of this.
    
    .NOTES
    Contact information:
    https://github.com/BradyDonovan/
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Enter the web request method needed.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [Alias("WebRequestMethod")]
        [Microsoft.PowerShell.Commands.WebRequestMethod]$Method,
        [Parameter(Mandatory = $true, HelpMessage = 'Enter the URI of the resource you are targeting.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $false, HelpMessage = 'Enter the Body of the web request.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [System.Object]$Body,
        [Parameter(Mandatory = $false, HelpMessage = 'Enter any Headers to include with the request.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [System.Collections.Hashtable]$Headers,
        [Parameter(Mandatory = $false, HelpMessage = 'Enter the content type for your request.', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [String]$ContentType

    )
    process {
        #Configuration file check
        Try {
            #Gather default JenkinsSystemName from config file
            $JenkinsSystemName = Get-DefaultJenkinsServer
        }
        Catch {
            throw "Looks like you haven't run the setup. Please run Set-PowerJenkinsModuleConfig to continue."
        }

        #grab a cookie if there isn't one. Otherwise, test it and send a pass/fail.
        IF ($null -eq $sessionCookie) { 
            $sessionCookie = Invoke-JenkinsLogin
            $cookie = $true
        }
        ELSE {
            $irmSplat = @{
                Method        = 'GET'
                Uri           = "$JenkinsSystemName/jobs/"
                WebSession    = $sessionCookie
                ErrorVariable = 'cookieTestFailure'
            }

            #try-catching here allows me to not set $ErrorActionPreference. We're sending the output to $_ | Out-Null below to prevent it from hitting STDOUT.
            try {
                $cookieTest = Invoke-RestMethod @irmSplat
            } 
            catch {
                "$_" | Out-Null
            }
            
            IF ($cookieTestFailure) {
                $cookie = $false
            }
        }

        $preFlight = Invoke-JenkinsPreFlightCheck
        
        #if the cookie and server are valid.. ($sendCommand = $true)
        $sendCommand = ($cookie -and $preFlight)

        switch ($sendCommand) {
            $true {
                IF ($Method -eq 'POST') {
                    #grab a crumb
                    try {
                        $crumb = Get-JenkinsCrumb -webRequestSessionCookie $sessionCookie
                        $crumbCheck = Confirm-JenkinsCrumb -webRequestSessionCookie $sessionCookie -crumb $crumb
                    }
                    catch {
                        throw "Could not validate crumb. Reason $_"
                    }
                    IF ($crumbCheck -eq $true) {
                        $irmSplat = @{
                            Method     = $Method
                            Uri        = "$JenkinsSystemName/$Uri"
                            WebSession = $sessionCookie
                            Headers    = $crumb
                        }
                    }
                }    
                IF (($Method -eq 'POST') -and $Body) {
                    #grab a crumb
                    try {
                        $crumb = Get-JenkinsCrumb -webRequestSessionCookie $sessionCookie
                        $crumbCheck = Confirm-JenkinsCrumb -webRequestSessionCookie $sessionCookie -crumb $crumb
                    }
                    catch {
                        throw "Could not validate crumb. Reason $_"
                    }
                    IF ($crumbCheck -eq $true) {
                        $irmSplat = @{
                            Method     = $Method
                            Uri        = "$JenkinsSystemName/$Uri"
                            WebSession = $sessionCookie
                            Headers    = $crumb
                            Body       = $Body
                        }
                    }
                }
                IF (($Method -eq 'POST' -and $Body -and $ContentType)) {
                    #grab a crumb
                    try {
                        $crumb = Get-JenkinsCrumb -webRequestSessionCookie $sessionCookie
                        $crumbCheck = Confirm-JenkinsCrumb -webRequestSessionCookie $sessionCookie -crumb $crumb
                    }
                    catch {
                        throw "Could not validate crumb. Reason $_"
                    }
                    IF ($crumbCheck -eq $true) {
                        $irmSplat = @{
                            Method      = $Method
                            Uri         = "$JenkinsSystemName/$Uri"
                            WebSession  = $sessionCookie
                            Headers     = $crumb
                            Body        = $Body
                            ContentType = $ContentType
                        }
                    }                    
                }
                IF ($Method -eq 'GET') {
                    $irmSplat = @{
                        Method     = $Method
                        Uri        = "$JenkinsSystemName/$Uri"
                        WebSession = $sessionCookie
                    }
                }
            }    
            $false {
                throw "Checks failed. Either the target server was not valid or you don't have a valid cookie. Quitting."
            }    
        }
        $Response = Invoke-RestMethod @irmSplat
        Return $Response
    }
}
function Invoke-JenkinsPreFlightChecks {
    <#
    .SYNOPSIS
    Run preflight checks to prepare the active session for working with the Jenkins API.
    
    .DESCRIPTION
    Preflight checks include: 
        Validating a Jenkins instance to ensure you aren't POSTing your creds to a malicous server.
        If valid, login to the server and obtain a CSRF token (crumb) from it. The token allows you to POST to anything in Jenkins. POSTing is typically reserved for administrative actions like creating, modifying, or deleting jobs.
        Finally, return both the crumb and session cookie to be used in successive actions.
        If anything is found to be invalid (server or crumb), the cmdlet will throw a terminating error and the script will stop.
    
    .EXAMPLE
    $preFlight = Invoke-JenkinsPreFlightChecks
    IF ($preFlight = $true) {
        #Do stuff
    }

    .OUTPUTS
    You will receive a Hashtable containing both the crumb and session cookie. Use it for successive actions.
    
    .NOTES
    Contact information:
    https://github.com/BradyDonovan/
    #>
    [CmdletBinding()]
    param(

    )
    process {
        #Configuration file check
        Try {
            #Gather default JenkinsSystemName from config file
            $JenkinsSystemName = Get-DefaultJenkinsServer
        }
        Catch {
            throw "Looks like you haven't run the setup. Please run Set-PowerJenkinsModuleConfig to continue."
        }

        Try {
            #set TLS version appropriate to Jenkins
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

            #Validate the server, and if you don't have a session cookie and crumb already.
            IF ((Confirm-JenkinsServer -ComputerName $JenkinsSystemName).Valid -eq $true) {
                $valid = $true
            }
            ELSE {
                $valid = $false
                throw "Not a valid Jenkins server. Do NOT send your credentials to it. Quitting."
            } 
            Return $valid
        }
        Catch {
            throw "Preflight checks failed. Reason: $_"
        }
    }
}