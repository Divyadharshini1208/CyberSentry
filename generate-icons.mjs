import fs from 'fs';
import zlib from 'zlib';

function crc32(buf) {
  let table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c;
  }
  let crc = 0 ^ (-1);
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xFF];
  }
  return (crc ^ (-1)) >>> 0;
}

function makeChunk(type, data) {
  const len = data.length;
  const chunk = Buffer.alloc(12 + len);
  chunk.writeUInt32BE(len, 0);
  chunk.write(type, 4, 4, 'ascii');
  data.copy(chunk, 8);
  const typeAndData = chunk.subarray(4, 8 + len);
  chunk.writeUInt32BE(crc32(typeAndData), 8 + len);
  return chunk;
}

function generateSentinelXIcon(size) {
  // Raw scanlines: each line is [filter=0, R, G, B, A * size]
  const rowSize = 1 + size * 4;
  const rawData = Buffer.alloc(rowSize * size);

  const cx = size / 2;
  const cy = size / 2;
  const radius = size * 0.45;

  for (let y = 0; y < size; y++) {
    const rowOffset = y * rowSize;
    rawData[rowOffset] = 0; // Filter None

    for (let x = 0; x < size; x++) {
      const pxOffset = rowOffset + 1 + x * 4;
      const dx = (x - cx) / radius;
      const dy = (y - cy) / radius;
      const dist = Math.sqrt(dx * dx + dy * dy);

      // Shield geometry: top half is curved/rounded rect, bottom half tapers to point
      const nx = Math.abs(x - cx) / (size * 0.4);
      const ny = (y - size * 0.15) / (size * 0.7);

      let inShield = false;
      if (ny >= 0 && ny <= 1) {
        if (ny < 0.4) {
          inShield = nx <= 0.95;
        } else {
          // taper to bottom
          const taper = 0.95 - (ny - 0.4) * 1.5;
          inShield = nx <= Math.max(0, taper);
        }
      }

      if (inShield) {
        // Border vs fill
        // Check if near edge
        const isBorder = (nx > 0.75 && ny < 0.4) || (ny >= 0.4 && nx > (0.95 - (ny - 0.4) * 1.5 - 0.18)) || ny < 0.08 || ny > 0.92;
        
        // Check for 'X' or center core
        const inCore = Math.abs(dx) < 0.25 && Math.abs(dy) < 0.25;
        const isCross = (Math.abs(dx - dy) < 0.16 || Math.abs(dx + dy) < 0.16) && Math.abs(dx) < 0.55 && Math.abs(dy) < 0.55;

        if (isCross) {
          // Electric Cyan for the X
          rawData[pxOffset] = 0;     // R
          rawData[pxOffset + 1] = 229; // G
          rawData[pxOffset + 2] = 255; // B (00E5FF)
          rawData[pxOffset + 3] = 255; // Alpha
        } else if (isBorder) {
          // Electric Blue for shield border
          rawData[pxOffset] = 0;     // R
          rawData[pxOffset + 1] = 112; // G
          rawData[pxOffset + 2] = 243; // B (#0070F3)
          rawData[pxOffset + 3] = 255;
        } else {
          // Deep navy shield background (#0B132B)
          rawData[pxOffset] = 11;
          rawData[pxOffset + 1] = 19;
          rawData[pxOffset + 2] = 43;
          rawData[pxOffset + 3] = 240;
        }
      } else {
        // Transparent outside shield
        rawData[pxOffset] = 0;
        rawData[pxOffset + 1] = 0;
        rawData[pxOffset + 2] = 0;
        rawData[pxOffset + 3] = 0;
      }
    }
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // 8-bit depth
  ihdr[9] = 6; // RGBA color type
  ihdr[10] = 0; // deflate
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // non-interlaced

  const idatData = zlib.deflateSync(rawData);

  const pngSig = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const ihdrChunk = makeChunk('IHDR', ihdr);
  const idatChunk = makeChunk('IDAT', idatData);
  const iendChunk = makeChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([pngSig, ihdrChunk, idatChunk, iendChunk]);
}

for (const size of [16, 48, 128]) {
  const png = generateSentinelXIcon(size);
  fs.writeFileSync(`extension/icons/icon${size}.png`, png);
  console.log(`Generated extension/icons/icon${size}.png (${png.length} bytes)`);
}

