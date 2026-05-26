import type { OTPAuthURIOptions } from './types.js';

const QR_API = 'https://api.qrserver.com/v1/create-qr-code/';

export function generateQRCodeURL(uri: string, size = 200): string {
  return `${QR_API}?data=${encodeURIComponent(uri)}&size=${size}x${size}`;
}

export function generateOTPAuthURI(options: OTPAuthURIOptions): string {
  const { type, secret, issuer, accountName, algorithm, digits } = options;

  if (type !== 'totp' && type !== 'hotp') throw new Error('OTPAuthURI: type must be totp or hotp');
  if (!secret) throw new Error('OTPAuthURI: secret is required');
  if (!issuer) throw new Error('OTPAuthURI: issuer is required');
  if (!accountName) throw new Error('OTPAuthURI: accountName is required');
  if (type === 'hotp' && (options.counter === undefined || !Number.isInteger(options.counter) || options.counter < 0)) {
    throw new Error('OTPAuthURI: counter must be a non-negative integer for HOTP');
  }

  const safeIssuer = issuer.replace(/:/g, '');
  const label = `${encodeURIComponent(safeIssuer)}:${encodeURIComponent(accountName)}`;
  const query = new URLSearchParams({ secret });
  query.set('issuer', safeIssuer);
  if (algorithm && algorithm !== 'SHA1') query.set('algorithm', algorithm);
  if (digits && digits !== 6) query.set('digits', String(digits));
  if (type === 'totp') {
    if (options.period && options.period !== 30) query.set('period', String(options.period));
  }
  if (type === 'hotp') {
    query.set('counter', String(options.counter!));
  }

  return `otpauth://${type}/${label}?${query.toString().replace(/\+/g, '%20').replace(/%3D/g, '=')}`;
}
