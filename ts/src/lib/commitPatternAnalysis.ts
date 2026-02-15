/**
 * Commit Pattern Analysis
 *
 * Analyzes author behavior and repo structure from git history for
 * dependency confusion and supply-chain risk. Feeds into ML detection.
 */

import { execSync } from 'child_process';

const GIT_TIMEOUT = 10000;

export interface CommitMessagePatterns {
  messages: string[];
  suspiciousCount: number;
  emptyCount: number;
  anomalyScore: number;
}

export interface DiffPatterns {
  recentCommitsWithLargeDiffs: number;
  avgAdditions: number;
  avgDeletions: number;
  anomalyScore: number;
}

export interface CommitPatterns {
  authorCount: number;
  totalCommitCount: number;
  firstCommitDate: Date | null;
  lastCommitDate: Date | null;
  dateRangeDays: number | null;
  branchCount: number;
  recentCommitCount90d: number;
  recentCommitCount30d: number;
  hasMultipleAuthors: boolean;
  dominantAuthorShare: number;
  repoRoot: string | null;
  hasGitHistory: boolean;
  commitMessagePatterns?: CommitMessagePatterns;
  diffPatterns?: DiffPatterns;
  messageAnomalyScore?: number;
  diffAnomalyScore?: number;
}

/**
 * Get repo root for a path (or null if not in a git repo)
 */
export function getRepoRoot(dir: string): string | null {
  try {
    const root = execSync('git rev-parse --show-toplevel', {
      cwd: dir,
      encoding: 'utf8',
      timeout: GIT_TIMEOUT,
    }).trim();
    return root || null;
  } catch {
    return null;
  }
}

/**
 * Run a git command safely; returns null on error or no repo
 */
function git(cmd: string, cwd: string): string | null {
  try {
    return execSync(cmd, { cwd, encoding: 'utf8', timeout: GIT_TIMEOUT }).trim();
  } catch {
    return null;
  }
}

// Suspicious commit message substrings (noise, vague, or typo-squat style)
const SUSPICIOUS_MESSAGE_PATTERNS = [
  /^fix$/i,
  /^update$/i,
  /^wip$/i,
  /^bump$/i,
  /^merge$/i,
  /^initial commit$/i,
  /^first commit$/i,
  /^asdf$/i,
  /^test$/i,
  /^[.\s]+$/, // only dots/whitespace
  /^[a-f0-9]{8,}$/i, // only hex (possible hash as message)
];
const MAX_RECENT_MESSAGES = 20;

/**
 * Analyze recent commit messages for suspicious patterns
 */
function analyzeCommitMessagePatterns(cwd: string): CommitMessagePatterns {
  const result: CommitMessagePatterns = {
    messages: [],
    suspiciousCount: 0,
    emptyCount: 0,
    anomalyScore: 0,
  };
  const out = git(`git log -${MAX_RECENT_MESSAGES} --format=%s HEAD`, cwd);
  if (!out) return result;
  const messages = out.split('\n').filter(Boolean);
  result.messages = messages.slice(0, MAX_RECENT_MESSAGES);
  let suspicious = 0;
  let empty = 0;
  for (const msg of result.messages) {
    const trimmed = msg.trim();
    if (!trimmed) {
      empty++;
      continue;
    }
    if (SUSPICIOUS_MESSAGE_PATTERNS.some((p) => p.test(trimmed))) suspicious++;
  }
  result.suspiciousCount = suspicious;
  result.emptyCount = empty;
  if (result.messages.length > 0) {
    const suspiciousRatio = (suspicious + empty) / result.messages.length;
    result.anomalyScore = Math.min(1, suspiciousRatio * 1.5); // 0–1
  }
  return result;
}

/**
 * Analyze recent diff patterns (large deletions, single-file mass changes)
 */
function analyzeDiffPatterns(cwd: string): DiffPatterns {
  const result: DiffPatterns = {
    recentCommitsWithLargeDiffs: 0,
    avgAdditions: 0,
    avgDeletions: 0,
    anomalyScore: 0,
  };
  const numCommits = 10;
  const out = git(`git log -${numCommits} --numstat --format= HEAD`, cwd);
  if (!out) return result;
  const lines = out.split('\n');
  let totalAdd = 0;
  let totalDel = 0;
  let commitsWithDiffs = 0;
  let largeDiffCommits = 0;
  let currentAdd = 0;
  let currentDel = 0;
  for (const line of lines) {
    const m = line.match(/^(\d+)\s+(\d+)\s+/);
    if (m) {
      const add = parseInt(m[1]!, 10) || 0;
      const del = parseInt(m[2]!, 10) || 0;
      currentAdd += add;
      currentDel += del;
    } else {
      if (currentAdd + currentDel > 0) {
        commitsWithDiffs++;
        if (currentDel > 500 || currentAdd > 2000) largeDiffCommits++;
        totalAdd += currentAdd;
        totalDel += currentDel;
      }
      currentAdd = 0;
      currentDel = 0;
    }
  }
  if (currentAdd + currentDel > 0) {
    commitsWithDiffs++;
    if (currentDel > 500 || currentAdd > 2000) largeDiffCommits++;
    totalAdd += currentAdd;
    totalDel += currentDel;
  }
  result.recentCommitsWithLargeDiffs = largeDiffCommits;
  result.avgAdditions = commitsWithDiffs > 0 ? Math.round(totalAdd / commitsWithDiffs) : 0;
  result.avgDeletions = commitsWithDiffs > 0 ? Math.round(totalDel / commitsWithDiffs) : 0;
  if (commitsWithDiffs > 0) {
    result.anomalyScore = Math.min(
      1,
      (largeDiffCommits / commitsWithDiffs) * 0.5 + (result.avgDeletions > 300 ? 0.3 : 0)
    );
  }
  return result;
}

/**
 * Analyze commit patterns: authors, activity, repo structure
 */
export function analyzeCommitPatterns(packagePath: string): CommitPatterns {
  const result: CommitPatterns = {
    authorCount: 0,
    totalCommitCount: 0,
    firstCommitDate: null,
    lastCommitDate: null,
    dateRangeDays: null,
    branchCount: 0,
    recentCommitCount90d: 0,
    recentCommitCount30d: 0,
    hasMultipleAuthors: false,
    dominantAuthorShare: 0,
    repoRoot: null,
    hasGitHistory: false,
  };

  const root = getRepoRoot(packagePath);
  if (!root) return result;

  result.repoRoot = root;
  const cwd = root;

  // Total commit count
  const countStr = git('git rev-list --count HEAD', cwd);
  if (countStr) {
    result.totalCommitCount = parseInt(countStr, 10) || 0;
    result.hasGitHistory = result.totalCommitCount > 0;
  }

  // First and last commit dates
  const firstCi = git('git log -1 --format=%ci --reverse HEAD', cwd);
  const lastCi = git('git log -1 --format=%ci HEAD', cwd);
  if (firstCi) result.firstCommitDate = new Date(firstCi);
  if (lastCi) result.lastCommitDate = new Date(lastCi);
  if (result.firstCommitDate && result.lastCommitDate) {
    result.dateRangeDays = Math.max(
      0,
      (result.lastCommitDate.getTime() - result.firstCommitDate.getTime()) / (1000 * 60 * 60 * 24)
    );
  }

  // Author counts (shortlog: "  123\tAuthor Name")
  const shortlog = git('git shortlog -s -n HEAD', cwd);
  if (shortlog) {
    const lines = shortlog.split('\n').filter(Boolean);
    result.authorCount = lines.length;
    result.hasMultipleAuthors = result.authorCount > 1;
    if (lines.length > 0 && result.totalCommitCount > 0) {
      const firstLine = lines[0]!;
      const match = firstLine.match(/^\s*(\d+)/);
      if (match) {
        const topCommits = parseInt(match[1]!, 10);
        result.dominantAuthorShare = topCommits / result.totalCommitCount;
      }
    }
  }

  // Branch count (local + remote)
  const branchOut = git('git branch -a', cwd);
  if (branchOut) result.branchCount = branchOut.split('\n').filter((line) => line.trim()).length;

  // Recent activity (last 90 and 30 days)
  const count90 = git('git rev-list --count HEAD --since="90 days ago"', cwd);
  const count30 = git('git rev-list --count HEAD --since="30 days ago"', cwd);
  if (count90 != null) result.recentCommitCount90d = parseInt(count90, 10) || 0;
  if (count30 != null) result.recentCommitCount30d = parseInt(count30, 10) || 0;

  // Pattern recognition: commit messages and diff patterns
  const messagePatterns = analyzeCommitMessagePatterns(cwd);
  const diffPatterns = analyzeDiffPatterns(cwd);
  result.commitMessagePatterns = messagePatterns;
  result.diffPatterns = diffPatterns;
  result.messageAnomalyScore = messagePatterns.anomalyScore;
  result.diffAnomalyScore = diffPatterns.anomalyScore;

  return result;
}

/**
 * Derive a simple anomaly score (0–1) from commit patterns for ML
 */
export function commitPatternAnomalyScore(patterns: CommitPatterns): number {
  if (!patterns.hasGitHistory) return 0.5; // No history is suspicious
  let score = 0;
  if (!patterns.hasMultipleAuthors) score += 0.2;
  if (patterns.totalCommitCount < 10) score += 0.2;
  if (patterns.dateRangeDays != null && patterns.dateRangeDays < 30) score += 0.2;
  if (patterns.recentCommitCount90d < 3) score += 0.15;
  if (patterns.dominantAuthorShare > 0.95 && patterns.authorCount > 1) score += 0.1;
  return Math.min(1, score);
}

export { analyzeCommitMessagePatterns, analyzeDiffPatterns };
