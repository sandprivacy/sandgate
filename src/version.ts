/**
 * The released version, compiled in: a standalone binary has no
 * package.json next to it to read. A test keeps this equal to
 * package.json, so a release cannot ship with a stale number.
 *
 * `sandgate --version` is also what makes an upgrade safe on a server —
 * `./sandgate.new --version && mv sandgate.new sandgate` only swaps in a
 * binary that actually runs.
 */
export const VERSION = "0.9.2";

/**
 * The last release that changed what a server runs: ssh-guard, its PAM
 * hook, the heartbeat. The phone offers "update available" to a server
 * older than THIS, not older than VERSION, so a release that only
 * touches the phone app or the relay does not ask every server to swap
 * its binary for nothing.
 *
 * Bump it to VERSION in any release that changes server-side behaviour
 * (src/ssh-guard*.ts, src/ssh-decision-cache.ts). Never above VERSION.
 */
export const SERVER_VERSION = "0.9.1";
