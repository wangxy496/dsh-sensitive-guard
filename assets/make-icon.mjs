// 从 icon.svg 的几何重绘 180x180 PNG（4x SSAA），无外部依赖
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';

const OUT = process.argv[2] || 'assets/icon-180.png';
const SIZE = 180, SS = 4, W = SIZE * SS;

// SVG 坐标 64x64
const K = 64 / W;

const C = {
  ring: [0x2a, 0x5f, 0x47, 255],
  body: [0x3d, 0x8f, 0x66, 255],
  hole: [0xe9, 0xf6, 0xef, 255],
};

function inRoundRect(x, y, rx, ry, w, h, r) {
  if (x < rx || x > rx + w || y < ry || y > ry + h) return false;
  const cx = Math.min(Math.max(x, rx + r), rx + w - r);
  const cy = Math.min(Math.max(y, ry + r), ry + h - r);
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
}

function dist(x, y, cx, cy) { return Math.hypot(x - cx, y - cy); }

function shackle(x, y) {
  // 半圆环：中心(32,23) 半径11 笔宽5，只取 y<=23
  if (y <= 23) {
    const d = dist(x, y, 32, 23);
    if (d >= 8.5 && d <= 13.5) return true;
  }
  // 两条竖腿
  if (Math.abs(x - 21) <= 2.5 && y >= 23 && y <= 34.5) return true;
  if (Math.abs(x - 43) <= 2.5 && y >= 23 && y <= 34.5) return true;
  return false;
}

function bodyFill(x, y) { return inRoundRect(x, y, 13, 31, 38, 27, 7); }
function bodyStroke(x, y) {
  return bodyFill(x, y) && !inRoundRect(x, y, 14.5, 32.5, 35, 24, 5.5);
}
function keyHole(x, y) {
  if (dist(x, y, 32, 41) <= 4.2) return true;
  return inRoundRect(x, y, 30, 43, 4, 9, 2);
}

// 逐像素（SSAA 累加）
const px = Buffer.alloc(SIZE * SIZE * 4);
for (let oy = 0; oy < SIZE; oy++) {
  for (let ox = 0; ox < SIZE; ox++) {
    let ar = 0, ag = 0, ab = 0, aa = 0;
    for (let sy = 0; sy < SS; sy++) {
      for (let sx = 0; sx < SS; sx++) {
        const x = (ox * SS + sx + 0.5) * K;
        const y = (oy * SS + sy + 0.5) * K;
        let col = null;
        if (keyHole(x, y)) col = C.hole;
        else if (bodyStroke(x, y)) col = C.ring;
        else if (bodyFill(x, y)) col = C.body;
        else if (shackle(x, y)) col = C.ring;
        if (col) { ar += col[0]; ag += col[1]; ab += col[2]; aa += 255; }
      }
    }
    const n = SS * SS;
    const i = (oy * SIZE + ox) * 4;
    const a = aa / n;
    if (a > 0) {
      px[i] = Math.round(ar / (aa / 255));
      px[i + 1] = Math.round(ag / (aa / 255));
      px[i + 2] = Math.round(ab / (aa / 255));
    }
    px[i + 3] = Math.round(a);
  }
}

// --- PNG 编码 ---
const crcTable = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0); ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;

const raw = Buffer.alloc(SIZE * (SIZE * 4 + 1));
for (let y = 0; y < SIZE; y++) {
  raw[y * (SIZE * 4 + 1)] = 0;
  px.copy(raw, y * (SIZE * 4 + 1) + 1, y * SIZE * 4, (y + 1) * SIZE * 4);
}

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);

mkdirSync(OUT.replace(/[\\/][^\\/]+$/, ''), { recursive: true });
writeFileSync(OUT, png);
console.log('wrote', OUT, png.length, 'bytes', SIZE + 'x' + SIZE);
