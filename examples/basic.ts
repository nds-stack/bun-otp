import { generateSecret, totp, hotp } from '../src/index';

async function main() {
  // Generate a new secret
  const secret = generateSecret();
  console.log('Secret:', secret);

  // TOTP example
  const code = await totp({ secret, digits: 6 });
  console.log('TOTP code:', code);

  const isValid = await totp.verify({ secret, token: code });
  console.log('TOTP valid:', isValid);

  // HOTP example
  const hotpCode = await hotp({ secret, counter: 0 });
  console.log('HOTP code (counter=0):', hotpCode);
}

main().catch(console.error);
