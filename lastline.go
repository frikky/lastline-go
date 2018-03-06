package lastline

import (
	"encoding/json"
	"fmt"
	"github.com/levigross/grequests"
	"io/ioutil"
	"os"
	"time"
)

type lastlinedata struct {
	Url      string `json:"lastlineurl"`
	Username string `json:"lastlineuser"`
	Password string `json:"lastlinepw"`
	Ro       grequests.RequestOptions
	Session  *grequests.Session
}

type historyData struct {
	Username           string `json:"username"`
	Status             string `json:"status"`
	taskObjectFilename string `json:"task_subject_filename"`
	TaskSubjectSha1    string `json:"task_subject_sha1"`
	TaskUuid           string `json:"task_uuid"`
	TaskSubjectMd5     string `json:"task_subject_md5"`
	TaskSubjectUrl     string `json:"task_subject_url"`
	AnalysisHistoryId  string `json:"analysis_history_id"`
	Title              string `json:"title"`
	Score              int    `json:"score"`
}

// urlanalysis
type Data struct {
	Submission        string          `json:"submission"`
	TaskUuid          string          `json:"task_uuid"`
	Reports           []Reports       `json:"reports"`
	ChildTasks        []ChildTasks    `json:"child_tasks"`
	Score             int             `json:"score"`
	MaliciousActivity []string        `json:"malicious_activity"`
	AnalysisSubject   AnalysisSubject `json:"analysis_subject"`
}

type History struct {
	Success int           `json:"success"`
	Data    []historyData `json:"data"`
	Raw     []byte
}

type MetaData struct {
	Name                      string `json:"name"`
	MetadataType              string `json:"metadata_type"`
	Score                     int    `json:"score"`
	AnalysisTerminationReason string `json:"analysis_termination_reason"`
}

type DetailedReport struct {
	StrType   string `json:"str_type"`
	StrLen    int64  `json:"str_len"`
	Value     string `json:"value"`
	SourceUrl string `json:"source_url"`
}

type Reports struct {
	Relevance      float64  `json:"relevance"`
	ReportUuid     string   `json:"report_uuid"`
	ReportVersions []string `json:"report_versions"`
	Description    string   `json:"description"`
}

type ChildTasks struct {
	TaskUuid         string `json:"task_uuid"`
	Score            int    `json:"score"`
	Tag              string `json:"tag"`
	ParentReportUuid string `json:"parent_report_uuid"`
}

type AnalysisSubject struct {
	Url string `json:"url"`
}

type Format struct {
	BuildVersion int    `json:"build_version"`
	MajorVersion int    `json:"major_version"`
	Name         string `json:"name"`
	MinorVersion int    `json:"minor_version"`
}

// Major data: analysis/network/requests/[data here]
// Missing addin_environment, Analysis (This one is big)
//Analysis              Analysis `json:"analysis"`
type Report struct {
	Activities            []string `json:"activities"`
	Uuid                  string   `json:"uuid"`
	Format                Format   `json:"format"`
	AnalysisEngineVersion int64    `json:"analysis_engine_versioos"`
}

type ReportData struct {
	TaskUuid          string          `json:"task_uuid"`
	Reports           []Reports       `json:"reports"`
	ChildTasks        []ChildTasks    `json:"child_tasks"`
	Score             int             `json:"score"`
	MaliciousActivity []string        `json:"malicious_activity"`
	AnalysisSubject   AnalysisSubject `json:"analysis_subject"`
	Report            Report          `json:"report"`
}

type TotalReport struct {
	Success   int        `json:"Success"`
	Score     int        `json:"score"`
	Data      ReportData `json:"data"`
	Error     string     `json:"error"`
	ErrorCode int        `json:"error_code"`
	Raw       []byte     `json:"-"`
}

func (login *lastlinedata) GetProgress(uuid string) (*TotalReport, error) {
	url := fmt.Sprintf("%s/papi/analysis/get_progress.json?uuid=%s", login.Url, uuid)
	ret, err := login.Session.Get(url, &login.Ro)

	if err != nil {
		return &TotalReport{}, err
	}

	tmp := TotalReport{}
	_ = json.Unmarshal(ret.Bytes(), &tmp)
	tmp.Raw = ret.Bytes()

	return &tmp, nil
}

func (login *lastlinedata) GetReport(uuid string) (*TotalReport, error) {
	url := fmt.Sprintf("%s/papi/analysis/get_result.json?uuid=%s", login.Url, uuid)
	ret, err := login.Session.Get(url, &login.Ro)

	if err != nil {
		return &TotalReport{}, err
	}

	tmp := TotalReport{}
	_ = json.Unmarshal(ret.Bytes(), &tmp)
	tmp.Raw = ret.Bytes()

	return &tmp, nil
}

// Missing struct handler
func (login *lastlinedata) GetEvent(eventId int) *grequests.Response {
	url := fmt.Sprintf("%s/papi/net/event/get.json?event_id=%d", login.Url, eventId)
	fmt.Println(url)
	ret, err := login.Session.Get(url, &login.Ro)

	if err != nil {
		fmt.Println(err)
	}

	return ret
}

func (login *lastlinedata) GetReportArtifact(uuid string, reportuuid string, artifactName string) *grequests.Response {
	url := fmt.Sprintf("%s/papi/analysis/get_report_artifact?uuid=%s&report_uuid=%s&artifact_name=%s", login.Url, uuid, reportuuid, artifactName)
	fmt.Println(url)
	ret, err := login.Session.Get(url, &login.Ro)

	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(ret)

	return ret
}

func (login *lastlinedata) GetHistory(limit int32) *grequests.Session {
	url := fmt.Sprintf("%s/papi/analysis/get_history.json?limit=%d", login.Url, limit)
	ret, err := login.Session.Get(url, &login.Ro)

	if err != nil {
		fmt.Println(err)
	}

	tmp := History{}
	_ = json.Unmarshal(ret.Bytes(), &tmp)
	tmp.Raw = ret.Bytes()

	return login.Session
}

func (login *lastlinedata) SubmitUrl(url string) (*TotalReport, error) {
	requesturl := fmt.Sprintf("%s/papi/analysis/submit_url.json?url=%s", login.Url, url)
	ret, err := login.Session.Post(requesturl, &login.Ro)

	if err != nil {
		return &TotalReport{}, err
	}

	tmp := TotalReport{}
	_ = json.Unmarshal(ret.Bytes(), &tmp)
	tmp.Raw = ret.Bytes()

	return &tmp, err
}

func GetLastlineLogin(configpath string) *lastlinedata {
	var err error

	file, err := ioutil.ReadFile(configpath)
	if err != nil {
		//log.Fatal(err)
		fmt.Printf("Error getting lastline: %s\n", err)
		os.Exit(3)
	}

	tmp := new(lastlinedata)
	_ = json.Unmarshal(file, tmp)

	Ro := grequests.RequestOptions{
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		RequestTimeout:     time.Duration(10) * time.Second,
		InsecureSkipVerify: false,
	}

	tmp.Ro = Ro
	tmp.Session = grequests.NewSession(&tmp.Ro)

	return tmp
}

// Runs login an creates a session
func (login *lastlinedata) RunLogin() *grequests.Session {
	url := fmt.Sprintf("%s/papi/login.json?username=%s&password=%s", login.Url, login.Username, login.Password)
	ret, err := login.Session.Get(url, &login.Ro)

	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(ret)
	return login.Session
}
