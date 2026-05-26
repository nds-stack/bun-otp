type AlgorithmName = 'SHA1' | 'SHA256' | 'SHA512'

const ALGORITHM_MAP: Readonly<Record<AlgorithmName, 'sha1' | 'sha256' | 'sha512'>> = {
  SHA1: 'sha1',
  SHA256: 'sha256',
  SHA512: 'sha512',
};

export function hmacSign(
  key: Uint8Array,
  data: Uint8Array,
  algorithm: AlgorithmName = 'SHA1',
): Uint8Array {
  const hasher = new Bun.CryptoHasher(ALGORITHM_MAP[algorithm], key);
  hasher.update(data);
  return new Uint8Array(hasher.digest());
}
