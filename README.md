# Lastline API
Basic API for usage with Golang. 

Reference: https://user.lastline.com/papi-doc/api/html/analysis/overview.html

## Usage
Set up a config file for the API
```Bash
$ cat config.json
{
	"lastlineurl": "https://Base url to lastline instance",
	"lastlineuser": "APIemail",
	"lastlinepw": "APIpassword" 
}
```

Import config and create user session
```Go
import "github.com/frikky/lastline"

// Get login info
configpath := "config.json"
lastline := lastline.GetLastlineLogin(configpath)
lastline.Session = lastline.RunLogin()
```

Example scan a URL and get the report when it finishes
```Go
response, _ := lastline.SubmitUrl("https://google.com")
report, _ := lastline.GetProgress(response.Data.TaskUuid)
if report.Success == 1 {
	newreport, _ := lastline.GetReport(response.Data.TaskUuid)
}
```

## Missing  
* Only supports JSON currently 
* Some functions
* Parts of json callback aren't mapped to structs
* Some functions still use grequests.Response
* COMMENTS :D
