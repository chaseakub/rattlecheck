// Reads a GitHub source tarball (.tar.gz) as a stream and keeps only the files
// the caller asks for. Everything else is skipped without being held in memory,
// and every size is capped: the input is whatever a stranger pushed to a repo.

const BLOCK = 512;
const decoder = new TextDecoder();

class Reader {
  constructor(stream, maxBytes) {
    this.reader = stream.getReader();
    this.chunks = [];
    this.have = 0;
    this.total = 0;
    this.maxBytes = maxBytes;
    this.done = false;
  }

  async fill(n) {
    while (this.have < n && !this.done) {
      const { value, done } = await this.reader.read();
      if (done) {
        this.done = true;
        break;
      }
      this.total += value.byteLength;
      if (this.total > this.maxBytes) throw new TarError('The repository is too large to check.');
      this.chunks.push(value);
      this.have += value.byteLength;
    }
    return this.have >= n;
  }

  // Exactly n bytes, or null at a clean end of stream.
  async read(n) {
    if (!(await this.fill(n))) {
      if (this.have === 0) return null;
      throw new TarError('The archive ended in the middle of a file.');
    }
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const head = this.chunks[0];
      const take = Math.min(head.byteLength, n - off);
      out.set(head.subarray(0, take), off);
      off += take;
      if (take === head.byteLength) this.chunks.shift();
      else this.chunks[0] = head.subarray(take);
    }
    this.have -= n;
    return out;
  }

  async skip(n) {
    let left = n;
    while (left > 0) {
      if (this.have === 0 && !(await this.fill(1))) throw new TarError('The archive ended in the middle of a file.');
      const head = this.chunks[0];
      const take = Math.min(head.byteLength, left);
      if (take === head.byteLength) this.chunks.shift();
      else this.chunks[0] = head.subarray(take);
      this.have -= take;
      left -= take;
    }
  }

  async cancel() {
    try {
      await this.reader.cancel();
    } catch {
      // already closed
    }
  }
}

export class TarError extends Error {}

const text = (bytes, start, len) => {
  let end = start;
  while (end < start + len && bytes[end] !== 0) end++;
  return decoder.decode(bytes.subarray(start, end));
};

// pax records: "<len> key=value\n", repeated.
function paxRecords(bytes) {
  const out = {};
  let i = 0;
  while (i < bytes.length) {
    let sp = i;
    while (sp < bytes.length && bytes[sp] !== 0x20) sp++;
    const len = Number(decoder.decode(bytes.subarray(i, sp)));
    if (!Number.isInteger(len) || len <= 0 || i + len > bytes.length) break;
    const record = decoder.decode(bytes.subarray(sp + 1, i + len - 1));
    const eq = record.indexOf('=');
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    i += len;
  }
  return out;
}

/**
 * @param {ReadableStream<Uint8Array>} gzipped
 * @param {object} opts
 * @param {(path: string) => boolean} opts.want   path is relative to the repo root
 * @param {number} opts.maxUnpackedBytes  cap on the whole unpacked archive
 * @param {number} opts.maxKeptBytes      cap on the files kept, all together
 * @param {number} opts.maxKeptFiles
 * @returns {Promise<{files: Map<string, string>, commit: string|null}>}
 */
export async function readTarGz(gzipped, { want, maxUnpackedBytes, maxKeptBytes, maxKeptFiles }) {
  const reader = new Reader(gzipped.pipeThrough(new DecompressionStream('gzip')), maxUnpackedBytes);
  const files = new Map();
  let commit = null;
  let kept = 0;
  let longPath = null;

  try {
    for (;;) {
      const header = await reader.read(BLOCK);
      if (!header) break;
      if (header.every((b) => b === 0)) break; // end-of-archive marker
      const size = parseInt(text(header, 124, 12).trim() || '0', 8);
      if (!Number.isFinite(size) || size < 0) throw new TarError('The archive is not a valid tar file.');
      const type = String.fromCharCode(header[156] || 0x30);
      const padded = Math.ceil(size / BLOCK) * BLOCK;

      if (type === 'g' || type === 'x') {
        if (size > 1024 * 1024) throw new TarError('The archive is not a valid tar file.');
        const records = paxRecords((await reader.read(padded)).subarray(0, size));
        if (type === 'g' && /^[0-9a-f]{40}$/.test(records.comment ?? '')) commit = records.comment;
        if (type === 'x' && records.path) longPath = records.path;
        continue;
      }

      const prefix = text(header, 345, 155);
      const full = longPath ?? (prefix ? `${prefix}/${text(header, 0, 100)}` : text(header, 0, 100));
      longPath = null;
      // GitHub wraps everything in one folder, "<repo>-<ref>/".
      const slash = full.indexOf('/');
      const rel = slash === -1 ? '' : full.slice(slash + 1);

      if (type === '0' && rel && want(rel)) {
        if (files.size >= maxKeptFiles) throw new TarError('The repository has too many migration files to check.');
        kept += size;
        if (kept > maxKeptBytes) throw new TarError('The migrations are too large to check.');
        const body = await reader.read(padded);
        files.set(rel, decoder.decode(body.subarray(0, size)));
      } else {
        await reader.skip(padded);
      }
    }
  } finally {
    await reader.cancel();
  }
  return { files, commit };
}
