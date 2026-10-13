/** Member tenure snapshot for history-sharer election. */
export type MemberTenure = { userId: string; joinedAt: number };

/**
 * Deterministic oldest-online election for automatic history backfill.
 * The requester never elects itself; ties break by user id so every caller
 * agrees without coordination. Presence stays server-side: callers pass the
 * online set in, nothing is broadcast. Null when nobody eligible is online.
 */
export function electHistorySharer(
  members: MemberTenure[],
  onlineUserIds: ReadonlySet<string>,
  requesterId: string
): string | null {
  let best: MemberTenure | null = null;
  for (const m of members) {
    if (m.userId === requesterId) continue;
    if (!onlineUserIds.has(m.userId)) continue;
    if (
      !best ||
      m.joinedAt < best.joinedAt ||
      (m.joinedAt === best.joinedAt && m.userId < best.userId)
    ) {
      best = m;
    }
  }
  return best?.userId ?? null;
}
