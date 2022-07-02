package main

type Config struct {
	BackendStorage      BackendStorage `yaml:"backendStorage"`
	Rules               Rules          `yaml:"rules"`
	NamespaceRestricted []string       `yaml:"namespaceRestricted"`
}
type BackendStorage struct {
	ArtifactsBucketName  string `yaml:"artifacts-bucket-name"`
	PublicKeysBucketName string `yaml:"public-keys-bucket-name"`
}
type OwaspDependencyCheck struct {
	MaxCriticalSeverity int `yaml:"max-critical-severity"`
	MaxHighSeverity     int `yaml:"max-high-severity"`
	MaxMediumServerity  int `yaml:"max-medium-serverity"`
	MaxLowSeverity      int `yaml:"max-low-severity"`
}
type Kubesec struct {
	MinScore int `yaml:"min-score"`
}
type Rules struct {
	OwaspDependencyCheck OwaspDependencyCheck `yaml:"owasp-dependency-check"`
	Kubesec              Kubesec              `yaml:"kubesec"`
}