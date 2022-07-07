package main

import "time"

type DependencyCheckOutput struct {
	ReportSchema string         `json:"reportSchema"`
	ScanInfo     ScanInfo       `json:"scanInfo"`
	ProjectInfo  ProjectInfo    `json:"projectInfo"`
	Dependencies []Dependencies `json:"dependencies"`
}
type DataSource struct {
	Name      string `json:"name"`
	Timestamp string `json:"timestamp"`
}
type ScanInfo struct {
	EngineVersion string       `json:"engineVersion"`
	DataSource    []DataSource `json:"dataSource"`
}
type Credits struct {
	Nvd      string `json:"NVD"`
	Npm      string `json:"NPM"`
	Retirejs string `json:"RETIREJS"`
	Ossindex string `json:"OSSINDEX"`
}
type ProjectInfo struct {
	Name       string    `json:"name"`
	ReportDate time.Time `json:"reportDate"`
	Credits    Credits   `json:"credits"`
}
type VendorEvidence struct {
	Type       string `json:"type"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
	Name       string `json:"name"`
	Value      string `json:"value"`
}
type ProductEvidence struct {
	Type       string `json:"type"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
	Name       string `json:"name"`
	Value      string `json:"value"`
}
type EvidenceCollected struct {
	VendorEvidence  []VendorEvidence  `json:"vendorEvidence"`
	ProductEvidence []ProductEvidence `json:"productEvidence"`
	VersionEvidence []interface{}     `json:"versionEvidence"`
}
type Packages struct {
	ID         string `json:"id"`
	Confidence string `json:"confidence"`
}
type VulnerabilityIds struct {
	ID         string `json:"id"`
	Confidence string `json:"confidence"`
	URL        string `json:"url"`
}
type Cvssv2 struct {
	Score                   float64 `json:"score"`
	AccessVector            string  `json:"accessVector"`
	AccessComplexity        string  `json:"accessComplexity"`
	Authenticationr         string  `json:"authenticationr"`
	ConfidentialImpact      string  `json:"confidentialImpact"`
	IntegrityImpact         string  `json:"integrityImpact"`
	AvailabilityImpact      string  `json:"availabilityImpact"`
	Severity                string  `json:"severity"`
	Version                 string  `json:"version"`
	ExploitabilityScore     string  `json:"exploitabilityScore"`
	ImpactScore             string  `json:"impactScore"`
	UserInteractionRequired string  `json:"userInteractionRequired"`
}
type Cvssv3 struct {
	BaseScore             float64 `json:"baseScore"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseSeverity          string  `json:"baseSeverity"`
	ExploitabilityScore   string  `json:"exploitabilityScore"`
	ImpactScore           string  `json:"impactScore"`
	Version               string  `json:"version"`
}
type References struct {
	Source string `json:"source"`
	URL    string `json:"url"`
	Name   string `json:"name"`
}
type Software struct {
	ID                     string `json:"id"`
	VulnerabilityIDMatched string `json:"vulnerabilityIdMatched"`
	VersionEndExcluding    string `json:"versionEndExcluding"`
}
type VulnerableSoftware struct {
	Software Software `json:"software"`
}
type Vulnerabilities struct {
	Source             string               `json:"source"`
	Name               string               `json:"name"`
	Severity           string               `json:"severity"`
	Cvssv2             Cvssv2               `json:"cvssv2"`
	Cvssv3             Cvssv3               `json:"cvssv3"`
	Cwes               []string             `json:"cwes"`
	Description        string               `json:"description"`
	Notes              string               `json:"notes"`
	References         []References         `json:"references"`
	VulnerableSoftware []VulnerableSoftware `json:"vulnerableSoftware"`
}
type PackageIds struct {
	ID string `json:"id"`
}
type RelatedDependencies struct {
	IsVirtual  bool         `json:"isVirtual"`
	FileName   string       `json:"fileName"`
	FilePath   string       `json:"filePath"`
	PackageIds []PackageIds `json:"packageIds"`
}
type Dependencies struct {
	IsVirtual           bool                  `json:"isVirtual"`
	FileName            string                `json:"fileName"`
	FilePath            string                `json:"filePath"`
	EvidenceCollected   EvidenceCollected     `json:"evidenceCollected"`
	Packages            []Packages            `json:"packages,omitempty"`
	License             string                `json:"license,omitempty"`
	VulnerabilityIds    []VulnerabilityIds    `json:"vulnerabilityIds,omitempty"`
	Vulnerabilities     []Vulnerabilities     `json:"vulnerabilities,omitempty"`
	RelatedDependencies []RelatedDependencies `json:"relatedDependencies,omitempty"`
	Md5                 string                `json:"md5,omitempty"`
	Sha1                string                `json:"sha1,omitempty"`
	Sha256              string                `json:"sha256,omitempty"`
}
