package cmd

type EventLog struct {
	UserInfo                       string       `json:"userInfo"`
	UID                            string       `json:"uid"`
	Namespace                      string       `json:"namespace"`
	Operations                     string       `json:"operations"`
	Allowed                        bool         `json:"allowed"`
	KubecsecDetailLink             string       `json:"kubecsec-detail-link"`
	OwaspDependencyCheckDetailLink string       `json:"owasp-dependency-check-detail-link"`
	ScannerScore                   ScannerScore `json:"scanner-score"`
	Result                         []Result     `json:"result"`
	Message                        string       `json:"message"`
}
type Severity struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}
type ScannerScore struct {
	Severity Severity `json:"severity"`
	Kubesec  int      `json:"kubesec"`
}
type Result struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}
