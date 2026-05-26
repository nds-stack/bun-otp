// Type workaround for TS6 SharedArrayBuffer incompatibility
type AlgorithmName = 'SHA1' | 'SHA256' | 'SHA512'

const ALGORITHM_MAP: Record<AlgorithmName, string> = {
  SHA1: 'SHA-1',
  SHA256: 'SHA-256',
  SHA512: 'SHA-512',
};

export async function hmacSign(
  key: Uint8Array,
  data: Uint8Array,
  algorithm: AlgorithmName = 'SHA1',
): Promise<Uint8Array> {
  const hashName = ALGORITHM_MAP[algorithm];
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key as unknown as BufferSource,
    { name: 'HMAC', hash: hashName },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data as unknown as BufferSource);
  return new Uint8Array(signature);
}
