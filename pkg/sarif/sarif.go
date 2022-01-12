package sarif

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

type Report struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}
type Run struct {
	Tool    RunTool     `json:"tool"`
	Results []RunResult `json:"results"`
}
type RunTool struct {
	Driver     RunToolDriver      `json:"driver"`
	Extensions []RunToolExtension `json:"extensions"`
}
type RunToolDriver struct {
	Name           string              `json:"name"`
	InformationUri string              `json:"informationUri"`
	FullName       string              `json:"fullName"`
	Version        string              `json:"version"`
	Rules          []RunToolDriverRule `json:"rules"`
}
type RunToolExtension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type RunToolDriverRule struct {
	Id                   string                                `json:"id"`
	Name                 *string                               `json:"name,omitempty"`
	DefaultConfiguration RunToolDriverRuleDefaultConfiguration `json:"defaultConfiguration"`
	ShortDescription     RunToolDriverRuleDescription          `json:"shortDescription"`
	FullDescription      RunToolDriverRuleDescription          `json:"fullDescription"`
	HelpUri              *string                               `json:"helpUri,omitempty"`
	Help                 *RunToolDriverRuleDescription         `json:"help,omitempty"`
}
type RunToolDriverRuleDefaultConfiguration struct {
	Level string `json:"level"`
}
type RunToolDriverRuleDescription struct {
	Text string `json:"text,omitempty"`
}
type RunResult struct {
	RuleId              string              `json:"ruleId"`
	Level               string              `json:"level"`
	Message             RunResultMessage    `json:"message"`
	Locations           []RunResultLocation `json:"locations,omitempty"`
	PartialFingerprints map[string]string   `json:"partialFingerprints,omitempty"`
}
type RunResultMessage struct {
	Text string `json:"text"`
}
type RunResultLocation struct {
	PhysicalLocation RunResultLocationPhysicalLocation `json:"physicalLocation"`
}
type RunResultLocationPhysicalLocation struct {
	ArtifactLocation RunResultLocationPhysicalLocationArtifactLocation `json:"artifactLocation"`
	Region           *RunResultLocationPhysicalLocationRegion          `json:"region,omitempty"`
}
type RunResultLocationPhysicalLocationArtifactLocation struct {
	Uri   string `json:"uri"`
	Index *uint  `json:"index,omitempty"`
}
type RunResultLocationPhysicalLocationRegion struct {
	StartLine   *uint `json:"startLine,omitempty"`
	StartColumn *uint `json:"startColumn,omitempty"`
	EndLine     *uint `json:"endLine,omitempty"`
	EndColumn   *uint `json:"endColumn,omitempty"`
}

func (report Report) WriteTo(outputPath string, verbose bool) error {
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if len(outputPath) > 0 {
		return ioutil.WriteFile(outputPath, jsonData, 0o644)
	}
	if verbose {
		log.Println(string(jsonData))
	}
	return nil
}
