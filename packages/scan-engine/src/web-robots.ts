import type { APIRequestContext } from 'playwright';

/**
 * Minimal robots.txt parser + fetcher (Phase 1.5 Sprint A2, T-A2.2).
 *
 * Why ours, not a dependency: the plan calls out that adding a dependency is a §4
 * stop. The robots.txt Allow/Disallow rules we need are simple text — User-agent
 * grouping plus per-path Allow/Disallow with "longest match wins, Allow wins ties"
 * (the Google-style interpretation). We do NOT need an HTML parser here. A small
 * focused parser stays in-tree and is fully test-covered.
 *
 * Scope (intentionally small for v1):
 *  - Honors the `User-agent: *` group (the default-bot group). We do not look up
 *    per-bot groups — Anthrion is a scanner, not a search crawler, and respecting
 *    the wildcard group is the conservative choice for any site that publishes
 *    robots.txt at all.
 *  - Recognizes `Allow:` and `Disallow:`. Anything else (Crawl-delay, Sitemap, …)
 *    is ignored — those do not affect the access decision.
 *  - Path matching: prefix match. The longest matching `Allow` or `Disallow` rule
 *    wins; on equal-length matches, `Allow` wins. An empty `Disallow:` line is a
 *    no-op (the spec: "Disallow:" with empty value means "nothing disallowed").
 *  - A non-200 fetch (404, 5xx, network error) is treated as "no robots.txt" → all
 *    URLs allowed. Conservative for crawl quality without ignoring real signals.
 *
 * `RobotsTxt` is the parsed rules; `fetchRobotsTxt` is the I/O that produces one.
 * Splitting them keeps the rules unit-testable without HTTP and lets the crawl
 * caller mock the fetch.
 */

interface Rule {
  /** `true` = Allow, `false` = Disallow. */
  allow: boolean;
  /** The path prefix the rule targets. Empty/`/` matches everything. */
  pattern: string;
}

/** Parsed robots.txt rules for the `*` user-agent group. */
export class RobotsTxt {
  private constructor(private readonly rules: readonly Rule[]) {}

  /**
   * Parse a robots.txt body. Returns a `RobotsTxt` carrying the `*` group's rules
   * in source order (longest-match-wins is computed at decision time, not here).
   */
  static parse(text: string): RobotsTxt {
    const lines = text.split(/\r?\n/);
    const rules: Rule[] = [];
    // We collect rules from groups whose `User-agent` list contains `*`. A group
    // is the run of `Allow`/`Disallow` lines following one or more `User-agent`
    // lines. We track whether the CURRENT group targets `*`.
    let currentTargetsStar = false;
    let inAfterUserAgent = false;

    for (const rawLine of lines) {
      const line = stripComment(rawLine).trim();
      if (line === '') {
        continue;
      }
      const colonIdx = line.indexOf(':');
      if (colonIdx === -1) {
        continue;
      }
      const field = line.slice(0, colonIdx).trim().toLowerCase();
      const value = line.slice(colonIdx + 1).trim();

      if (field === 'user-agent') {
        // A `User-agent` line either STARTS a new group, or CONTINUES the existing
        // group if no Allow/Disallow has appeared yet. The standard groups multiple
        // consecutive `User-agent` lines together.
        if (inAfterUserAgent) {
          currentTargetsStar = currentTargetsStar || value === '*';
        } else {
          currentTargetsStar = value === '*';
          inAfterUserAgent = true;
        }
        continue;
      }

      // Any non-user-agent directive ends the "collecting user-agents" phase for
      // the group. A subsequent User-agent line starts a NEW group.
      inAfterUserAgent = false;

      if (!currentTargetsStar) {
        continue;
      }
      if (field === 'allow') {
        // Per spec: an empty Allow is a no-op (does not enable anything).
        if (value !== '') {
          rules.push({ allow: true, pattern: value });
        }
      } else if (field === 'disallow') {
        // Per spec: an empty Disallow means "nothing disallowed" — a no-op for
        // our purposes (the absence of any rule is already permissive).
        if (value !== '') {
          rules.push({ allow: false, pattern: value });
        }
      }
      // All other fields (Crawl-delay, Sitemap, …) are ignored: they do not
      // affect the access decision.
    }
    return new RobotsTxt(rules);
  }

  /** A `RobotsTxt` with no rules — everything allowed. Used when no file exists. */
  static permissive(): RobotsTxt {
    return new RobotsTxt([]);
  }

  /**
   * Is the given URL path allowed? `path` should include the leading `/` and the
   * query string (the spec matches against path + query). Decision uses longest
   * matching rule; on equal length, `Allow` wins (Google-style robots.txt).
   *
   * No matching rule → allowed (the spec default when no Disallow targets the
   * path).
   */
  isAllowed(pathWithQuery: string): boolean {
    let bestLen = -1;
    let bestAllow = true;
    for (const rule of this.rules) {
      if (!pathWithQuery.startsWith(rule.pattern)) {
        continue;
      }
      if (rule.pattern.length > bestLen) {
        bestLen = rule.pattern.length;
        bestAllow = rule.allow;
      } else if (rule.pattern.length === bestLen && rule.allow) {
        // Tie-break: Allow wins.
        bestAllow = true;
      }
    }
    return bestLen === -1 ? true : bestAllow;
  }

  /** Number of effective rules — exposed for tests/diagnostics. */
  get ruleCount(): number {
    return this.rules.length;
  }
}

/** Strip a trailing `# …` comment from a line, respecting that `#` is the comment marker. */
function stripComment(line: string): string {
  const hashIdx = line.indexOf('#');
  return hashIdx === -1 ? line : line.slice(0, hashIdx);
}

/**
 * Fetch and parse robots.txt for an origin via Playwright's `APIRequestContext`.
 *
 * Why `APIRequestContext`: the existing web scan ALREADY does its HTTP through
 * Playwright (Page navigation), so this stays inside the same network layer the
 * sandbox already permits. The engine itself adds no new HTTP client.
 *
 * A 404, 5xx, or network failure → `RobotsTxt.permissive()` (treated as "no
 * robots.txt"). A 2xx with a body → parsed; the parser tolerates a malformed
 * body by simply collecting no rules (i.e. permissive).
 *
 * `timeoutMs` bounds the fetch so a hanging server cannot stall the crawl.
 */
export async function fetchRobotsTxt(
  request: APIRequestContext,
  origin: string,
  timeoutMs: number,
): Promise<RobotsTxt> {
  const robotsUrl = new URL('/robots.txt', origin).toString();
  let response;
  try {
    response = await request.get(robotsUrl, { timeout: timeoutMs, failOnStatusCode: false });
  } catch {
    // Network error / DNS failure / connection refused → treat as no robots.txt.
    return RobotsTxt.permissive();
  }
  const status = response.status();
  if (status < 200 || status >= 300) {
    return RobotsTxt.permissive();
  }
  let body: string;
  try {
    body = await response.text();
  } catch {
    return RobotsTxt.permissive();
  }
  return RobotsTxt.parse(body);
}
