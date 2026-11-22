import { isDDoSAttackReport } from './ddosReportContract';
import type { ExportJob } from './ddosExport';

// Bounds are additive over the supported closed report shapes, not export
// eligibility. See web/docs/ddos-source-budgets.md for the field census.
const REPORT_NODES = 1024 + 100 * (247 + 8 * 27 + 4 * 261);
const REPORT_CHARACTERS = 65536 + 100 * (247 * 64 + 8 * (5 * 32 + 2 * 32 + 16 * 128) + 4 * 8192);
const SOURCE_CHARACTERS = 256 * (64 + 4) * 2 + 2 * 200 * 2 + 64 + 32 + 128;

// JSON response boundary, not an arbitrary JavaScript object sandbox. Charge
// work before the semantic guard (which has some legacy coercion paths).
function bounded(value: unknown, maxCharacters: number, source = false, maxNodes = 100000): boolean {
  let nodes = 0, characters = 0;
  const visit = (v: unknown, depth: number, path = ''): boolean => {
    if (++nodes > maxNodes || depth > 16) return false;
    if (v == null || typeof v === 'boolean') return true;
    if (typeof v === 'number') return Number.isFinite(v);
    if (typeof v === 'string') { characters += v.length; return characters <= maxCharacters; }
    if (typeof v !== 'object') return false;
    if (Array.isArray(v)) return v.length <= (source && path === 'internal_networks' ? 256 : source && path === 'source.link_types' ? 65536 : 100) && v.every(item => visit(item, depth + 1));
    let keys = 0;
    for (const key in v) {
      if (!Object.hasOwn(v, key)) continue;
      if (++keys > 64 || !visit(key, depth + 1) || !visit((v as Record<string, unknown>)[key], depth + 1, path ? `${path}.${key}` : key)) return false;
    }
    return true;
  };
  return visit(value, 0);
}

export function ddosSourceSnapshot(report: unknown, job?: ExportJob): string | null {
  // Never traverse unrelated job metadata. These are ALL fields read by the
  // synchronous JSON/BPF export and passive-selection authority checks.
  const source = job === undefined ? null : {
    id: job.id, dataset_id: job.dataset_id, source_type: job.source_type,
    internal_networks: job.internal_networks,
    source: job.source === undefined ? undefined : { sha256: job.source?.sha256, link_types: job.source?.link_types },
  };
  if (!bounded(report, REPORT_CHARACTERS, false, REPORT_NODES) || !bounded(source, SOURCE_CHARACTERS, true)) return null;
  try {
    if (!isDDoSAttackReport(report)) return null;
    // The report guard closes these nested semantic shapes; the preceding
    // budget also bounds fields that legacy guard branches do not consume.
    // Explicit root projection avoids treating successful validation as a
    // license to serialize an arbitrary response envelope or job object.
    return JSON.stringify({
      version: report.version, catalog_version: report.catalog_version,
      verdict: report.verdict, confidence: report.confidence,
      primary_finding_id: report.primary_finding_id, summary: report.summary,
      findings: report.findings, recommendations: report.recommendations,
      warnings: report.warnings, limitations: report.limitations,
      omitted_finding_count: report.omitted_finding_count,
      normal_reference: report.normal_reference, source,
    });
  } catch { return null; }
}
