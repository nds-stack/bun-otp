const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const ALPHABET_MAP: Readonly<Record<string, number>> = Object.freeze(
  Object.fromEntries(ALPHABET.split('').map((c, i) => [c, i])),
);

export function base32Encode(data: Uint8Array): string {
  const result: string[] = [];
  let buffer = 0;
  let bits = 0;

  for (const byte of data) {
    buffer = (buffer << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      bits -= 5;
      result.push(ALPHABET[(buffer >>> bits) & 31]);
    }

    buffer = buffer & ((1 << bits) - 1);
  }

  if (bits > 0) {
    result.push(ALPHABET[(buffer << (5 - bits)) & 31]);
  }

  while (result.length % 8 !== 0) {
    result.push('=');
  }

  return result.join('');
}

export function base32Decode(str: string): Uint8Array {
  if (str.length === 0) {
    throw new Error('base32Decode: empty input');
  }
  const cleaned = str.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
  if (cleaned.length === 0) {
    throw new Error('base32Decode: input contains only padding characters');
  }
  if (cleaned.length > 1_000_000) {
    throw new RangeError('base32Decode: input exceeds maximum length of 1,000,000 characters');
  }
  const outLen = Math.ceil(cleaned.length * 5 / 8);
  const out = new Uint8Array(outLen);
  let buffer = 0;
  let bits = 0;
  let idx = 0;

  for (const char of cleaned) {
    const value = ALPHABET_MAP[char];
    if (value === undefined) {
      throw new Error(`Invalid base32 character: '${char}'`);
    }

    buffer = (buffer << 5) | value;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      out[idx++] = (buffer >>> bits) & 0xff;
      buffer = buffer & ((1 << bits) - 1);
    }
  }

  return out;
}
