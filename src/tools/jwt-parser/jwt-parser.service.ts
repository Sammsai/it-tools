import {
  HmacSHA256,
  HmacSHA384,
  HmacSHA512,
  enc,
} from 'crypto-js';
import { ALGORITHM_DESCRIPTIONS, CLAIM_DESCRIPTIONS } from './jwt-parser.constants';

export interface SplitJwtResult {
  headerPart: string
  payloadPart: string
  signaturePart: string
  isValidFormat: boolean
}

export interface DecodedJwtResult {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  headerRaw: string
  payloadRaw: string
  signature: string
  alg: string
  typ: string
}

export interface ClaimInfo {
  claim: string
  value: string
  description?: string
  friendlyValue?: string
}

export interface SignatureVerificationResult {
  status: 'valid' | 'invalid' | 'unsigned' | 'unsupported'
  message: string
}

export function base64UrlDecode(base64Url: string): string {
  try {
    let b64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) {
      b64 += '=';
    }
    const words = enc.Base64.parse(b64);
    return enc.Utf8.stringify(words);
  }
  catch {
    return '';
  }
}

export function base64UrlEncode(utf8Str: string): string {
  const words = enc.Utf8.parse(utf8Str);
  const b64 = enc.Base64.stringify(words);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function splitJwt(jwt: string): SplitJwtResult {
  const trimmed = jwt.trim();
  if (!trimmed) {
    return {
      headerPart: '',
      payloadPart: '',
      signaturePart: '',
      isValidFormat: false,
    };
  }

  const parts = trimmed.split('.');
  if (parts.length < 2 || parts.length > 3) {
    return {
      headerPart: '',
      payloadPart: '',
      signaturePart: '',
      isValidFormat: false,
    };
  }

  return {
    headerPart: parts[0] ?? '',
    payloadPart: parts[1] ?? '',
    signaturePart: parts[2] ?? '',
    isValidFormat: true,
  };
}

export function parseJwt(jwt: string): DecodedJwtResult | null {
  const { headerPart, payloadPart, signaturePart, isValidFormat } = splitJwt(jwt);
  if (!isValidFormat) {
    return null;
  }

  const headerStr = base64UrlDecode(headerPart);
  const payloadStr = base64UrlDecode(payloadPart);

  if (!headerStr || !payloadStr) {
    return null;
  }

  try {
    const header = JSON.parse(headerStr) as Record<string, unknown>;
    const payload = JSON.parse(payloadStr) as Record<string, unknown>;
    const alg = typeof header.alg === 'string' ? header.alg : '';
    const typ = typeof header.typ === 'string' ? header.typ : 'JWT';

    return {
      header,
      payload,
      headerRaw: JSON.stringify(header, null, 2),
      payloadRaw: JSON.stringify(payload, null, 2),
      signature: signaturePart,
      alg,
      typ,
    };
  }
  catch {
    return null;
  }
}

export function computeHmacSignature({
  data,
  secret,
  alg,
  secretIsBase64 = false,
}: {
  data: string
  secret: string
  alg: string
  secretIsBase64?: boolean
}): string {
  if (!data || !alg) {
    return '';
  }

  let secretParsed: any = secret;
  if (secretIsBase64) {
    try {
      secretParsed = enc.Base64.parse(secret);
    }
    catch {
      secretParsed = secret;
    }
  }

  let hash;
  if (alg === 'HS256') {
    hash = HmacSHA256(data, secretParsed);
  }
  else if (alg === 'HS384') {
    hash = HmacSHA384(data, secretParsed);
  }
  else if (alg === 'HS512') {
    hash = HmacSHA512(data, secretParsed);
  }
  else {
    return '';
  }

  const b64 = enc.Base64.stringify(hash);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function verifyJwtSignature({
  jwt,
  secret,
  secretIsBase64 = false,
}: {
  jwt: string
  secret: string
  secretIsBase64?: boolean
}): SignatureVerificationResult {
  const { headerPart, payloadPart, signaturePart, isValidFormat } = splitJwt(jwt);
  if (!isValidFormat) {
    return { status: 'invalid', message: 'Malformed JWT format.' };
  }

  const decoded = parseJwt(jwt);
  if (!decoded) {
    return { status: 'invalid', message: 'Unable to decode JWT header/payload.' };
  }

  const { alg } = decoded;

  if (alg === 'none' || !signaturePart) {
    return { status: 'unsigned', message: 'Token is unsigned (alg: "none").' };
  }

  if (['HS256', 'HS384', 'HS512'].includes(alg)) {
    const dataToSign = `${headerPart}.${payloadPart}`;
    const expectedSig = computeHmacSignature({
      data: dataToSign,
      secret,
      alg,
      secretIsBase64,
    });

    if (expectedSig && expectedSig === signaturePart) {
      return { status: 'valid', message: 'Signature Verified' };
    }
    return { status: 'invalid', message: 'Invalid Signature' };
  }

  return {
    status: 'unsupported',
    message: `Signature verification for algorithm ${alg} is not supported directly in browser.`,
  };
}

export function generateJwtFromParts({
  headerJson,
  payloadJson,
  secret = '',
  secretIsBase64 = false,
}: {
  headerJson: string
  payloadJson: string
  secret?: string
  secretIsBase64?: boolean
}): string {
  try {
    const headerObj = JSON.parse(headerJson) as Record<string, unknown>;
    const payloadObj = JSON.parse(payloadJson) as Record<string, unknown>;

    const headerPart = base64UrlEncode(JSON.stringify(headerObj));
    const payloadPart = base64UrlEncode(JSON.stringify(payloadObj));
    const data = `${headerPart}.${payloadPart}`;

    const alg = typeof headerObj.alg === 'string' ? headerObj.alg : 'HS256';

    if (alg === 'none') {
      return `${data}.`;
    }

    if (['HS256', 'HS384', 'HS512'].includes(alg)) {
      const sig = computeHmacSignature({ data, secret, alg, secretIsBase64 });
      return `${data}.${sig}`;
    }

    return `${data}.`;
  }
  catch {
    return '';
  }
}

export function formatTimestamp(timestamp: unknown): {
  formatted: string
  relative: string
  isPast: boolean
} | null {
  if (timestamp === null || timestamp === undefined) {
    return null;
  }

  const num = Number(timestamp);
  if (Number.isNaN(num) || num <= 0) {
    return null;
  }

  const date = new Date(num > 1e11 ? num : num * 1000);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  const now = Date.now();
  const diffMs = date.getTime() - now;
  const isPast = diffMs < 0;
  const absSeconds = Math.floor(Math.abs(diffMs) / 1000);

  let relative = '';
  if (absSeconds < 60) {
    relative = `${absSeconds}s`;
  }
  else if (absSeconds < 3600) {
    relative = `${Math.floor(absSeconds / 60)}m`;
  }
  else if (absSeconds < 86400) {
    relative = `${Math.floor(absSeconds / 3600)}h`;
  }
  else {
    relative = `${Math.floor(absSeconds / 86400)}d`;
  }

  const relativeText = isPast ? `${relative} ago` : `in ${relative}`;
  const formatted = date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');

  return {
    formatted,
    relative: relativeText,
    isPast,
  };
}

export function getClaimsList(record: Record<string, unknown>): ClaimInfo[] {
  return Object.entries(record).map(([claim, value]) => {
    const description = CLAIM_DESCRIPTIONS[claim];
    let friendlyValue: string | undefined;

    if (['exp', 'nbf', 'iat', 'auth_time'].includes(claim)) {
      const ts = formatTimestamp(value);
      if (ts) {
        friendlyValue = `${ts.formatted} (${ts.relative})`;
      }
    }
    else if (claim === 'alg' && typeof value === 'string') {
      friendlyValue = ALGORITHM_DESCRIPTIONS[value];
    }

    const formattedValue = typeof value === 'object' && value !== null
      ? JSON.stringify(value)
      : String(value);

    return {
      claim,
      value: formattedValue,
      description,
      friendlyValue,
    };
  });
}

// Backward compatibility
export function decodeJwt({ jwt }: { jwt: string }) {
  const parsed = parseJwt(jwt);
  if (!parsed) {
    return { header: [], payload: [] };
  }

  return {
    header: getClaimsList(parsed.header),
    payload: getClaimsList(parsed.payload),
  };
}
