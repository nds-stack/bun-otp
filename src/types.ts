export interface TOTPOptions {
  secret: string
  period?: number
  digits?: number
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512'
  timestamp?: number
}

export interface TOTPVerifyOptions extends TOTPOptions {
  token: string
  window?: number
}

export interface HOTPOptions {
  secret: string
  counter: number
  digits?: number
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512'
}

export interface HOTPVerifyOptions extends HOTPOptions {
  token: string
  window?: number
}
