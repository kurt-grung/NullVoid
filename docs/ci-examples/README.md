# CI examples

Copy the file for your platform into your repository and adjust the target path and `--fail-on` threshold. Each runs `nullvoid` and fails the pipeline on HIGH or CRITICAL findings; see [../CI_INTEGRATION.md](../CI_INTEGRATION.md) for SARIF upload and exit-code details.

| File | Platform | Destination |
| --- | --- | --- |
| `gitlab-ci.yml` | GitLab CI | `.gitlab-ci.yml` |
| `azure-pipelines.yml` | Azure DevOps | `azure-pipelines.yml` |
| `Jenkinsfile` | Jenkins (declarative) | `Jenkinsfile` |
| `travis.yml` | Travis CI | `.travis.yml` |
| `circleci-config.yml` | CircleCI | `.circleci/config.yml` |

GitHub Actions is in the [README](../../README.md#ci).
