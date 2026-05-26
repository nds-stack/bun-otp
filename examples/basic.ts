import { generateSecret, totp, hotp } from '../src/index.js';

// Generate a new secret
const secret = generateSecret();
console.log('Secret:', secret);

// TOTP example (sync — no await needed)
const code = totp({ secret, digits: 6 });
console.log('TOTP code:', code);

const isValid = totp.verify({ secret, token: code });
console.log('TOTP valid:', isValid);

// HOTP example
const hotpCode = hotp({ secret, counter: 0 });
console.log('HOTP code (counter=0):', hotpCode);
