import { intelligenceApi } from "./api";
import type { Domain, ValidationCandidateResponse } from "./api/types";

export type PriorityMap = Map<string, ValidationCandidateResponse>;

/**
 * Best-effort cve_id -> priority-queue entry lookup, used to join priority score/
 * support status/linked-experiments onto vulnerability rows. GET /priority-queue has
 * no cve_id filter (only domain/support_status/priority_gte), so this fetches the
 * API's max page (200, ordered highest-priority-first) per requested domain and
 * indexes it by cve_id.
 *
 * A CVE ranked below the top 200 for its domain, or in a domain the priority queue
 * never lists (unsupported domains never appear there), will simply be absent from
 * the map - callers must render that as "priority data not available", never guess
 * or fall back to a fabricated score.
 */
export async function buildPriorityMap(domains: (Domain | null)[]): Promise<PriorityMap> {
  const uniqueDomains = [...new Set(domains.filter((d): d is Domain => d !== null))];
  const results = await Promise.all(
    uniqueDomains.map((domain) => intelligenceApi.getPriorityQueue({ domain, limit: 200 }).catch(() => null))
  );
  const map: PriorityMap = new Map();
  for (const result of results) {
    if (!result) continue;
    for (const candidate of result.candidates) {
      map.set(candidate.cve_id, candidate);
    }
  }
  return map;
}
