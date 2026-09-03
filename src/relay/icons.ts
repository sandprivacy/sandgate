import { deflateSync } from "node:zlib";

/**
 * The sandgate mark: a geometric gate (two posts, two lintels) in amber on
 * the warm dark ground. Drawn from axis-aligned rectangles so the PNG app
 * icons can be generated in pure Node — no rasterizer dependency — and stay
 * pixel-crisp at every size. The SVG twin is used inline in the PWA.
 */

const BG: [number, number, number] = [20, 18, 16]; // #141210
const AMBER: [number, number, number] = [217, 164, 65]; // #D9A441

// Gate geometry as fractions of the canvas: [x0, y0, x1, y1]
const GATE_RECTS: [number, number, number, number][] = [
  [0.18, 0.26, 0.82, 0.34], // top lintel
  [0.26, 0.42, 0.74, 0.48], // second bar
  [0.3, 0.34, 0.38, 0.78], // left post
  [0.62, 0.34, 0.7, 0.78], // right post
];

export const ICON_SVG =
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">` +
  `<rect width="100" height="100" rx="22" fill="#141210"/>` +
  GATE_RECTS.map(
    ([x0, y0, x1, y1]) =>
      `<rect x="${x0 * 100}" y="${y0 * 100}" width="${(x1 - x0) * 100}" height="${(y1 - y0) * 100}" rx="2.5" fill="#D9A441"/>`
  ).join("") +
  `</svg>`;

/** The bare glyph (transparent ground) for inline UI use. */
export const GLYPH_SVG_RECTS = GATE_RECTS.map(
  ([x0, y0, x1, y1]) =>
    `<rect x="${x0 * 24}" y="${y0 * 24}" width="${(x1 - x0) * 24}" height="${(y1 - y0) * 24}" rx="0.6"/>`
).join("");

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

const cache = new Map<number, Buffer>();

/** Render the app icon as a PNG at the given square size. */
export function iconPng(size: number): Buffer {
  const cached = cache.get(size);
  if (cached) return cached;

  const px = Buffer.alloc(size * size * 3);
  for (let i = 0; i < size * size; i++) {
    px[i * 3] = BG[0];
    px[i * 3 + 1] = BG[1];
    px[i * 3 + 2] = BG[2];
  }
  for (const [fx0, fy0, fx1, fy1] of GATE_RECTS) {
    const x0 = Math.round(fx0 * size);
    const x1 = Math.round(fx1 * size);
    const y0 = Math.round(fy0 * size);
    const y1 = Math.round(fy1 * size);
    for (let y = y0; y < y1; y++) {
      for (let x = x0; x < x1; x++) {
        const i = (y * size + x) * 3;
        px[i] = AMBER[0];
        px[i + 1] = AMBER[1];
        px[i + 2] = AMBER[2];
      }
    }
  }

  // Raw scanlines: filter byte 0 + RGB row.
  const raw = Buffer.alloc(size * (size * 3 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 3 + 1)] = 0;
    px.copy(raw, y * (size * 3 + 1) + 1, y * size * 3, (y + 1) * size * 3);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // color type: truecolor RGB
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", deflateSync(raw, { level: 9 })),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
  cache.set(size, png);
  return png;
}
