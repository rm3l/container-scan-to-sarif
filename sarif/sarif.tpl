{
  "version": "2.1.0",
  "$schema": "https://github.com/oasis-tcs/sarif-spec/blob/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "azure-container-scan",
          "informationUri": "https://github.com/Azure/container-scan",
          "fullName": "Azure Container Scan",
          "version": "v0.1",
          "extensions": [
            {
                "name": "Trivy",
                "version": "latest"
            },
            {
                "name": "Dockle",
                "version": "latest"
            }
          ],
          "rules": [
          ]
        }
      },
      "results": [
    {{- $t_first := true }}
    {{- range $result := . }}
        {{- $filePath := .Target }}
        {{- range $index, $vulnerability := .Vulnerabilities -}}
          {{- if $t_first -}}
            {{- $t_first = false -}}
          {{ else -}}
            ,
          {{- end }}
        {
          "ruleId": {{ printf "%s: %s-%s %s" $result.Target .PkgName .InstalledVersion .VulnerabilityID | toJson }},
          "ruleIndex": {{ $index }},
          "level": "{{ toSarifErrorLevel $vulnerability.Vulnerability.Severity }}",
          "message": {
            "text": {{ endWithPeriod (escapeString $vulnerability.Description) | printf "%q" }}
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "{{ toPathUri $filePath }}",
                "uriBaseId": "ROOTPATH"
              }
            }
          }]
        }
        {{- end -}}
      {{- end -}}
      ],
      "columnKind": "utf16CodeUnits",
      "originalUriBaseIds": {
        "ROOTPATH": {
          "uri": "/"
        }
      }
    }
  ]
}