/**
 * The released version, compiled in: a standalone binary has no
 * package.json next to it to read. A test keeps this equal to
 * package.json, so a release cannot ship with a stale number.
 *
 * `sandgate --version` is also what makes an upgrade safe on a server —
 * `./sandgate.new --version && mv sandgate.new sandgate` only swaps in a
 * binary that actually runs.
 */
export const VERSION = "0.9.1";
