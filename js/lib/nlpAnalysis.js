/**
 * NLP Analysis on package docs and GitHub issues
 *
 * Fetches README/description from npm registry and GitHub issues when repo URL is available.
 * Runs NLP pipeline: security keyword extraction, sentiment, suspicious phrase detection.
 */

const axios = require('axios');

const SECURITY_KEYWORDS = [
  'vulnerability', 'vulnerabilities', 'security', 'malware', 'virus', 'trojan',
  'backdoor', 'exploit', 'injection', 'xss', 'csrf', 'sqli', 'rce', 'deprecated',
  'unsafe', 'dangerous', 'obsolete', 'hack', 'bypass', 'leak', 'exfiltrate',
  'keylogger', 'spyware', 'rootkit', 'botnet', 'phishing', 'ransomware'
];

const SUSPICIOUS_PHRASES = [
  /deprecated\s+and\s+unsafe/i, /known\s+vulnerability/i, /security\s+issue/i,
  /do\s+not\s+use\s+in\s+production/i, /experimental\s+only/i, /use\s+at\s+your\s+own\s+risk/i,
  /no\s+longer\s+maintained/i, /abandoned\s+project/i, /unmaintained/i,
  /contains\s+malware/i, /potential\s+backdoor/i, /data\s+exfiltration/i,
  /wallet\s+hijack/i, /supply\s+chain\s+attack/i
];

const DEFAULT_NLP_CONFIG = {
  ENABLED: false,
  GITHUB_TOKEN: process.env.GITHUB_TOKEN || process.env.PHASE4_GITHUB_TOKEN || null,
  MAX_ISSUES: 30,
  SKIP_IF_NO_REPO: true,
  TIMEOUT_MS: 10000
};

async function fetchPackageDocs(packageName, version = 'latest', config = {}) {
  const timeout = config.TIMEOUT_MS ?? DEFAULT_NLP_CONFIG.TIMEOUT_MS;
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
    const res = await axios.get(url, {
      timeout,
      headers: { 'User-Agent': 'NullVoid-Security-Scanner/2.1.0' },
      validateStatus: (s) => s === 200
    });
    const data = res.data;
    if (!data || typeof data !== 'object') return null;

    let versionData = data.versions?.[version];
    if (!versionData && version === 'latest') {
      const latestTag = data['dist-tags']?.latest;
      versionData = latestTag ? data.versions?.[latestTag] : null;
    }
    if (!versionData) {
      const versions = Object.keys(data.versions || {});
      versionData = versions.length > 0 ? data.versions?.[versions[versions.length - 1]] : null;
    }
    if (!versionData) return null;

    const readme = typeof data.readme === 'string' ? data.readme : '';
    const description = typeof versionData.description === 'string' ? versionData.description : '';
    let repositoryUrl;
    const repo = versionData.repository || data.repository;
    if (repo) {
      if (typeof repo === 'string') repositoryUrl = repo;
      else if (repo.url) repositoryUrl = repo.url.replace(/^git\+/, '').replace(/\.git$/, '');
    }
    return { readme, description, repositoryUrl };
  } catch {
    return null;
  }
}

function parseGitHubRepoUrl(url) {
  const m = url.match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (m) return { owner: m[1], repo: m[2].replace(/\.git$/, '') };
  return null;
}

async function fetchGitHubIssues(repoUrl, options = {}) {
  const parsed = parseGitHubRepoUrl(repoUrl);
  if (!parsed) return [];
  const { owner, repo } = parsed;
  const maxIssues = options.maxIssues ?? DEFAULT_NLP_CONFIG.MAX_ISSUES;
  const timeout = options.timeout ?? DEFAULT_NLP_CONFIG.TIMEOUT_MS;
  try {
    const headers = {
      Accept: 'application/vnd.github.v3+json',
      'User-Agent': 'NullVoid-Security-Scanner/2.1.0'
    };
    if (options.token) headers['Authorization'] = `Bearer ${options.token}`;

    const res = await axios.get(
      `https://api.github.com/repos/${owner}/${repo}/issues`,
      {
        params: { state: 'all', per_page: Math.min(maxIssues, 100), sort: 'updated' },
        headers,
        timeout,
        validateStatus: (s) => s === 200
      }
    );
    const items = Array.isArray(res.data) ? res.data : [];
    return items.slice(0, maxIssues).map((item) => ({
      title: item.title || '',
      body: item.body || null,
      state: item.state || 'open',
      labels: (item.labels || []).map((l) => l.name || '')
    }));
  } catch {
    return [];
  }
}

function runNlpPipeline(text, additionalIssues = []) {
  const suspiciousPhrases = [];
  let securityKeywordCount = 0;
  const lower = text.toLowerCase();

  for (const kw of SECURITY_KEYWORDS) {
    const regex = new RegExp(`\\b${kw}\\b`, 'gi');
    const matches = text.match(regex);
    if (matches) securityKeywordCount += matches.length;
  }
  for (const pattern of SUSPICIOUS_PHRASES) {
    const m = text.match(pattern);
    if (m) suspiciousPhrases.push(m[0].trim());
  }
  suspiciousPhrases.push(...additionalIssues);

  const negativeWords = ['deprecated', 'unsafe', 'vulnerability', 'malware', 'dangerous', 'abandoned', 'broken'];
  let sentimentScore = 0.5;
  for (const w of negativeWords) {
    if (lower.includes(w)) sentimentScore -= 0.1;
  }
  sentimentScore = Math.max(0, Math.min(1, sentimentScore));

  const dedupedPhrases = [...new Set(suspiciousPhrases)];
  const keywordScore = Math.min(1, securityKeywordCount * 0.1);
  const phraseScore = Math.min(1, dedupedPhrases.length * 0.2);
  const securityScore = Math.min(1, (keywordScore + phraseScore) / 2);

  return {
    securityScore,
    suspiciousPhrases: dedupedPhrases,
    sentimentScore,
    issueSecurityCount: 0,
    nlpSecurityScore: securityScore,
    nlpSuspiciousCount: dedupedPhrases.length
  };
}

function analyzeDocsNLP(texts) {
  const combined = [texts.readme || '', texts.description || ''].filter(Boolean).join('\n');
  return runNlpPipeline(combined, []);
}

function analyzeIssuesNLP(issues) {
  const combined = issues.map((i) => `${i.title} ${i.body || ''}`).filter(Boolean).join('\n');
  const securityLabels = issues.filter((i) =>
    i.labels.some((l) => /security|vulnerability|bug|critical/i.test(l))
  ).length;
  const result = runNlpPipeline(combined, []);
  result.issueSecurityCount = securityLabels + (result.suspiciousPhrases.length > 0 ? 1 : 0);
  return result;
}

async function runNlpAnalysis(packageName, version = 'latest', config = {}) {
  const cfg = { ...DEFAULT_NLP_CONFIG, ...config };
  if (!cfg.ENABLED) return null;

  const docs = await fetchPackageDocs(packageName, version, cfg);
  if (!docs) return null;

  const docResult = analyzeDocsNLP({ readme: docs.readme, description: docs.description });
  let issues = [];
  if (docs.repositoryUrl && docs.repositoryUrl.includes('github.com')) {
    issues = await fetchGitHubIssues(docs.repositoryUrl, {
      token: cfg.GITHUB_TOKEN,
      maxIssues: cfg.MAX_ISSUES,
      timeout: cfg.TIMEOUT_MS
    });
  } else if (cfg.SKIP_IF_NO_REPO) {
    return { ...docResult, issueSecurityCount: 0 };
  }

  const issueResult = issues.length > 0 ? analyzeIssuesNLP(issues) : null;
  const merged = { ...docResult, issueSecurityCount: issueResult?.issueSecurityCount ?? 0 };
  if (issueResult) {
    merged.securityScore = Math.min(1, (docResult.securityScore + issueResult.securityScore) / 2);
    merged.nlpSecurityScore = merged.securityScore;
    merged.suspiciousPhrases = [...new Set([...docResult.suspiciousPhrases, ...issueResult.suspiciousPhrases])];
    merged.nlpSuspiciousCount = merged.suspiciousPhrases.length;
  }
  return merged;
}

module.exports = {
  fetchPackageDocs,
  fetchGitHubIssues,
  analyzeDocsNLP,
  analyzeIssuesNLP,
  runNlpAnalysis,
  DEFAULT_NLP_CONFIG
};
