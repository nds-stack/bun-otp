const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const ALPHABET_MAP: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) {
  ALPHABET_MAP[ALPHABET[i]] = i;
}

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
  const cleaned = str.replace(/=+$/, '').toUpperCase();
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (const char of cleaned) {
    const value = ALPHABET_MAP[char];
    if (value === undefined) {
      throw new Error(`Invalid base32 character: '${char}'`);
    }

    buffer = (buffer << 5) | value;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 0xff);
      buffer = buffer & ((1 << bits) - 1);
    }
  }

  return new Uint8Array(bytes);
}
