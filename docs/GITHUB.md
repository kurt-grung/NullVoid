# How NullVoid uses GitHub

> Also published as a blog post: [kurtgrung.com](https://kurtgrung.com/blog/how-nullvoid-uses-github/) · [dev.to](https://dev.to/kurt_grng_05ec30687d6ae8/how-nullvoid-uses-github-2lp5)

NullVoid is a static scanner for malicious code in npm packages and Node.js projects. GitHub data feeds it in three places: live vulnerability lookups during a scan, community signals about a package's source repository, and the training labels for its machine-learning models.

## 1. Live advisory lookups (GitHub Security Advisories)

For every declared dependency, NullVoid queries the [GitHub Advisory Database](https://github.com/advisories) through the GraphQL API (`https://api.github.com/graphql`). It asks for npm-ecosystem advisories affecting the package, then checks the installed version against each advisory's `vulnerableVersionRange` so only advisories that actually apply are reported.

Each matching advisory becomes a finding carrying:

- the GHSA ID and permalink, plus any CVE identifiers
- GitHub's severity (CRITICAL / HIGH / MODERATE / LOW) and CVSS score
- CWE classifications
- the first patched version, so the report can say what to upgrade to

GHSA is one of several IoC providers, alongside npm advisories, NVD and optionally Snyk. Results are cached and combined with the other sources. It is enabled by default; set `GITHUB_TOKEN` (or `NULLVOID_GITHUB_TOKEN`) for higher rate limits. See [IOC_USAGE.md](IOC_USAGE.md) for configuration.

Code: [`ts/src/lib/providers/ghsa.ts`](../ts/src/lib/providers/ghsa.ts)

## 2. Community signals from the source repository

When a package's `repository` field points at GitHub, NullVoid reads the repository's public metadata from the REST API (`GET /repos/{owner}/{repo}`) and uses its star count as one input (30% weight, alongside npm downloads and dependents) to a popularity score. That score feeds the dependency-confusion and ML detectors, so a brand-new package with no real repository behind it is treated differently from an established, widely starred project.

Code: [`ts/src/lib/communityAnalysis.ts`](../ts/src/lib/communityAnalysis.ts)

## 3. Training data for the ML models

NullVoid's dependency and behavioral models are retrained on a schedule by a GitHub Actions workflow ([`ml-model-retrain.yml`](../.github/workflows/ml-model-retrain.yml)). The export scripts page through the REST advisories endpoint (`GET /advisories?ecosystem=npm&type=malware`, plus `type=reviewed`), skip withdrawn advisories, and collect the affected npm packages as labelled examples. GitHub's curated malware advisories are what let the models learn what real npm supply-chain attacks look like, rather than relying on synthetic samples.

Code: [`ml-model/export-features.js`](../ml-model/export-features.js), [`ml-model/export-behavioral-features.js`](../ml-model/export-behavioral-features.js)

## Running NullVoid on GitHub

NullVoid also runs inside GitHub: it can emit SARIF, which GitHub code scanning picks up through `github/codeql-action/upload-sarif`, so findings show up in a repository's Security tab and on pull requests. The workflow is in the [README](../README.md) and [CI_INTEGRATION.md](CI_INTEGRATION.md).

## Support

Questions or problems: [open an issue](https://github.com/kurt-grung/NullVoid/issues) or email [caterer.01boars@icloud.com](mailto:caterer.01boars@icloud.com). Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).
