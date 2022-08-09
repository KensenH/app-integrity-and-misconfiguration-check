package cmd

type Config struct {
	Key            Key            `yaml:"key"`
	BackendStorage BackendStorage `yaml:"backendStorage"`
	Scanner        Scanner        `yaml:"scanner"`
	Script         Script         `yaml:"script"`
	Output         string
}
type Key struct {
	PrivateKey string `yaml:"private-key"`
	PublicKey  string `yaml:"public-key"`
}
type BackendStorage struct {
	ArtifactsBucketName  string `yaml:"artifacts-bucket-name"`
	PublicKeysBucketName string `yaml:"public-keys-bucket-name"`
}
type Scanner struct {
	OwaspDependencyCheckScan   string `yaml:"owasp-dependency-check-scan"`
	OwaspDependencyCheckOutput string `yaml:"owasp-dependency-check-output"`
	KubesecScan                bool   `yaml:"kubesec-scan"`
	KubesecOutput              string `yaml:"kubesec-output"`
}
type Script struct {
	Rm bool `yaml:"rm"`
}
