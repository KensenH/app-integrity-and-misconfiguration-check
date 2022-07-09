package main

type Config struct {
	BackendStorage      BackendStorage `yaml:"backendStorage"`
	Rules               Rules          `yaml:"rules"`
	NamespaceRestricted []string       `yaml:"namespaceRestricted"`
}
type BackendStorage struct {
	ArtifactsBucketName  string `yaml:"artifacts-bucket-name"`
	PublicKeysBucketName string `yaml:"public-keys-bucket-name"`
	LogBucketName        string `yaml:"log-bucket-name"`
}
type AcceptableBaseScore struct {
	AttackVector          string `yaml:"attack-vector"`
	AttackComplexity      string `yaml:"attack-complexity"`
	PrivilegesRequired    string `yaml:"privileges-required"`
	UserInteraction       string `yaml:"user-interaction"`
	Scope                 string `yaml:"scope"`
	ConfidentialityImpact string `yaml:"confidentiality-impact"`
	IntegrityImpact       string `yaml:"integrity-impact"`
	AvailabilityImpact    string `yaml:"availability-impact"`
}
type OwaspDependencyCheck struct {
	MaxCriticalSeverity int                 `yaml:"max-critical-severity"`
	MaxHighSeverity     int                 `yaml:"max-high-severity"`
	MaxMediumServerity  int                 `yaml:"max-medium-serverity"`
	MaxLowSeverity      int                 `yaml:"max-low-severity"`
	AcceptableBaseScore AcceptableBaseScore `yaml:"acceptable-base-score"`
}
type Kubesec struct {
	MinScore int `yaml:"min-score"`
}
type Rules struct {
	OwaspDependencyCheck OwaspDependencyCheck `yaml:"owasp-dependency-check"`
	Kubesec              Kubesec              `yaml:"kubesec"`
}
