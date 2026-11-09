# CI/CD integration

NullVoid exits `1` when a threat at or above `--fail-on` (default `high`) is found, `2` on a scan error and `0` otherwise, and writes SARIF for code-scanning upload. Ready-to-copy pipeline files for GitLab, Azure DevOps, Jenkins, Travis and CircleCI live in [ci-examples/](ci-examples/).

## SARIF Output for CI/CD Integration

NullVoid supports SARIF (Static Analysis Results Interchange Format) output for seamless integration with CI/CD pipelines and security tools.

### CI Integrations

### GitHub CI Actions Integration
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Install NullVoid
        run: npm install -g nullvoid
      
      - name: Run Security Scan
        run: nullvoid . --output sarif --sarif-file nullvoid-results.sarif
      
      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nullvoid-results.sarif
```

### CircleCI Integration

A ready-to-use CircleCI config is in [ci-examples/circleci-config.yml](ci-examples/circleci-config.yml). It installs dependencies, builds NullVoid, runs the scan, and stores the JSON report as an artifact.

```yaml
# .circleci/config.yml (excerpt)
jobs:
  security-scan:
    docker:
      - image: cimg/node:20
    steps:
      - checkout
      - run: npm ci
      - run: npm run build
      - run: node ts/dist/bin/nullvoid.js . --format json --output security-report.json
      - store_artifacts:
          path: security-report.json
```

### GitLab CI Integration
```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  image: node:20
  script:
    - npm install -g nullvoid
    - nullvoid . --output sarif --sarif-file nullvoid-results.sarif
  artifacts:
    reports:
      sarif: nullvoid-results.sarif
```

### Azure DevOps Integration
```yaml
# azure-pipelines.yml
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: NodeTool@0
  inputs:
    versionSpec: '20.x'
  displayName: 'Install Node.js'

- script: |
    npm install -g nullvoid
    nullvoid . --output sarif --sarif-file nullvoid-results.sarif
  displayName: 'Run NullVoid Security Scan'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'nullvoid-results.sarif'
    artifactName: 'sarif-results'
```

### Jenkins Integration
A declarative pipeline example is in [ci-examples/Jenkinsfile](ci-examples/Jenkinsfile). Copy to `Jenkinsfile` or add as a stage to your pipeline.

```groovy
// Jenkinsfile (excerpt)
stage('NullVoid Security Scan') {
  steps {
    sh 'npx nullvoid . --output json --sarif-file nullvoid-results.sarif'
  }
  post {
    always {
      archiveArtifacts artifacts: 'nullvoid-results.sarif', allowEmptyArchive: true
    }
  }
}
```

### SARIF Output Example
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "NullVoid",
        "version": "2.1.0",
        "informationUri": "https://github.com/kurt-grung/NullVoid"
      }
    },
    "results": [{
      "ruleId": "WALLET_HIJACKING",
      "level": "error",
      "message": {
        "text": "Package may contain wallet hijacking code"
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {
            "uri": "node_modules/suspicious-package/index.js"
          },
          "region": {
            "startLine": 42,
            "startColumn": 1
          }
        }
      }]
    }]
  }]
}
```

### Supported CI/CD Platforms
- **GitHub Security**: Automatic security alerts and PR checks
- **GitLab Security**: Security dashboard integration
- **Azure DevOps**: Security scanning in pipelines
- **Jenkins**: Security reporting plugins
- **SonarQube**: Code quality and security analysis
