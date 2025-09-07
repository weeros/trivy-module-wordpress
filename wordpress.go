package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-version"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/module/serialize"
	"github.com/aquasecurity/trivy/pkg/module/wasm"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Module interface {
	Version() int
	Name() string
}

type Analyzer interface {
	RequiredFiles() []string
	Analyze(filePath string) (*serialize.AnalysisResult, error)
}

type PostScanner interface {
	PostScanSpec() serialize.PostScanSpec
	PostScan(types.Results) (types.Results, error)
}

const (
	moduleVersion = 1
	name          = "wordpress-module"
)

func main() {}

func init() {
	wasm.RegisterModule(WordpressModule{})
}

type WordpressModule struct {
	// Cannot define fields as modules can't keep state.
}

func (WordpressModule) Version() int {
	return moduleVersion
}

func (WordpressModule) Name() string {
	return name
}

const typeWPVersion = "wordpress-version"

func (WordpressModule) RequiredFiles() []string {
	return []string{
		`wp-includes\/version.php`,
	}
}

func (WordpressModule) Analyze(filePath string) (*serialize.AnalysisResult, error) {
	f, err := os.Open(filePath) // e.g. filePath: /usr/src/wordpress/wp-includes/version.php
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var wpVersion string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "$wp_version") {
			continue
		}

		wasm.Info(fmt.Sprintf("line : %s", line))
		ss := strings.Split(line, "=")
		if len(ss) != 2 {
			return nil, fmt.Errorf("invalid wordpress version: %s", line)
		}

		// NOTE: it is an example; you actually need to handle comments, etc
		ss[1] = strings.TrimSpace(ss[1])
		ss[1] = strings.Trim(ss[1], `"`)
		ss[1] = strings.Trim(ss[1], `'`)
		ss[1] = strings.Trim(ss[1], `";`)
		ss[1] = strings.Trim(ss[1], `';`)
		wpVersion = strings.Trim(ss[1], `;`)
		wasm.Info(fmt.Sprintf("WordPress Version: %s", wpVersion))
	}


	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return &serialize.AnalysisResult{
		CustomResources: []ftypes.CustomResource{
			{
				Type:     typeWPVersion,
				FilePath: filePath,
				Data:     wpVersion,
			},
		},
	}, nil
}

func (WordpressModule) PostScanSpec() serialize.PostScanSpec {
	return serialize.PostScanSpec{
		Action: api.ActionInsert, // Add new vulnerabilities
	}
}

func (WordpressModule) PostScan(results types.Results) (types.Results, error) {
	// e.g. results
	// [
	//   {
	//     "Target": "",
	//     "Class": "custom",
	//     "CustomResources": [
	//       {
	//         "Type": "wordpress-version",
	//         "FilePath": "/usr/src/wordpress/wp-includes/version.php",
	//         "Layer": {
	//           "DiffID": "sha256:057649e61046e02c975b84557c03c6cca095b8c9accd3bd20eb4e432f7aec887"
	//         },
	//         "Data": "5.7.1"
	//       }
	//     ]
	//   }
	// ]
	affectedVersion, _ := version.NewConstraint(">=5.7, <7.7.2")
	var (
		vulnerable                           bool
		wpPath, wpVersionAffected string
	)
	for _, result := range results {
		if result.Class != types.ClassCustom {
			continue
		}

		for _, c := range result.CustomResources {
			wpPath = c.FilePath
			if c.Type != typeWPVersion {
				continue
			}

			wpVersion := c.Data.(string)
			if wpVersion != "" {
				wpVersionAffected = wpVersion
			}

			ver, err := version.NewVersion(wpVersion)
			if err != nil {
				return nil, err
			}

			if affectedVersion.Check(ver) {
				vulnerable = true
			}
			break
		}
	}

	if vulnerable {
		// Add CVE-2020-36326
		results = append(results, types.Result{
			Target: wpPath,
			Class:  types.ClassLangPkg,
			Type:   "wordpress",
			Vulnerabilities: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-36326",
					PkgName:          "wordpress",
					InstalledVersion: wpVersionAffected,
					FixedVersion:     "5.7.2",
					Vulnerability: dbTypes.Vulnerability{
						Title:    "PHPMailer 6.1.8 through 6.4.0 allows object injection through Phar Deserialization via addAttachment with a UNC pathname.",
						Severity: "CRITICAL",
					},
				},
				{
					VulnerabilityID:  "CVE-2018-19296",
					PkgName:          "wordpress",
					InstalledVersion: wpVersionAffected,
					FixedVersion:     "5.7.2",
					Vulnerability: dbTypes.Vulnerability{
						Title:    "PHPMailer before 5.2.27 and 6.x before 6.0.6 is vulnerable to an object injection attack.",
						Severity: "HIGH",
					},
				},
				{
					VulnerabilityID:  "CVE-2018-19216",
					PkgName:          "wordpress",
					InstalledVersion: wpVersionAffected,
					FixedVersion:     "6.7.2",
					Vulnerability: dbTypes.Vulnerability{
						Title:    "PHPMailer before 5.2.27 and 6.x before 6.0.6 is vulnerable to an object injection attack.",
						Severity: "CRITICAL",
					},
				},
			},
		})
	}
	return results, nil
}
