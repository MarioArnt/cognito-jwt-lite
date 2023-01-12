import { decode, verify as jwtVerify, VerifyOptions } from 'jsonwebtoken';
import convertToPem from 'jwk-to-pem';
import { get } from 'https';
import { IncomingMessage } from 'http';
export interface IDecodeOptions extends VerifyOptions {
  issuer: string;
  maxRetries?: number;
}

const DEFAULT_DISCOVERY_RETRIES = 2;

type ErrorCode =
  | 'NotMatchingKey'
  | 'TokenNotDecoded'
  | 'InvalidToken'
  | 'MissingKeyID'
  | 'ErrorFetchingKeys'
  | 'InvalidDiscoveryResponse'
  | 'InvalidIssuer'
  | 'CannotConvertFromJwkToPem'
  | 'JsonWebTokenError';

export class JwtError extends Error {
  code: ErrorCode;
  details: Error;
  constructor(code: ErrorCode, msg: string, details?: Error) {
    super(msg);
    this.code = code;
    this.details = details;
  }
}

interface IKey {
  alg: string;
  e: string;
  kid: string;
  kty: 'RSA';
  n: string;
  use: string;
}

const getDiscoveryUrl = (issuer: string): string => {
  return `${issuer}/.well-known/jwks.json`;
};

const invalidPayloadError = (discoveryURL: string) =>
  new JwtError('InvalidDiscoveryResponse', `API call to discovery URL ${discoveryURL} returned an invalid response`);

const throwError = (err: Error): Error => {
  return new JwtError('ErrorFetchingKeys', 'An error occurred retrieving public keys from Cognito API', err);
};

/**
 * Retry request on network failure or on 5xx
 */
const retry = (err: Error, attempt: number, retries: number, options: IDecodeOptions): Promise<Array<IKey>> => {
  return new Promise((resolve, reject) => {
    if (attempt >= retries) {
      return reject(throwError(err));
    }
    return getKeys(options, attempt + 1)
      .then(resolve)
      .catch(reject);
  });
};

/**
 * Verify that payload response is on the expected format
 */
const verifyResponse = (data: string): IKey[] => {
  const validated = JSON.parse(data) as { keys: IKey[] };
  if (validated.keys && Array.isArray(validated.keys) && validated.keys.every((key) => key.kid != null)) {
    return validated.keys;
  }
  throw new Error('Invalid Payload');
};

const onResponse = (
  response: IncomingMessage,
  data: string,
  attempt: number,
  retries: number,
  options: IDecodeOptions,
  url: string,
): Promise<Array<IKey>> => {
  return new Promise((resolve, reject) => {
    if (response.statusCode !== 200) {
      const error = new Error(`Server answered with status code ${response.statusCode}`);
      if (response.statusCode > 499 && response.statusCode < 600) {
        // Retry on 5XX
        return retry(error, attempt, retries, options).then(resolve).catch(reject);
      }
      return reject(throwError(error));
    }
    try {
      const keys = verifyResponse(data);
      return resolve(keys);
    } catch (e) {
      return reject(invalidPayloadError(url));
    }
  });
};

const getKeys = async (options: IDecodeOptions, attempt = 0): Promise<Array<IKey>> => {
  const discoveryURL = getDiscoveryUrl(options.issuer);
  const retries = options && options.maxRetries != null ? options.maxRetries : DEFAULT_DISCOVERY_RETRIES;
  return new Promise((resolve, reject) => {
    get(discoveryURL, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => onResponse(res, data, attempt, retries, options, discoveryURL).then(resolve).catch(reject));
    }).on('error', (err) => retry(err, attempt, retries, options).then(resolve).catch(reject));
  });
};

const buildKey = async (options: IDecodeOptions, kid: string) => {
  const keys = await getKeys(options);
  const matchingKey = keys.find((k) => k.kid === kid);
  if (!matchingKey) {
    throw new JwtError('NotMatchingKey', 'A key matching your token kid cannot  be found in Cognito public keys');
  }
  try {
    return convertToPem(matchingKey);
  } catch (e) {
    throw new JwtError('CannotConvertFromJwkToPem', 'Failed to convert matching JWK to PEM');
  }
};

const verifyJWT = async (token: string, key: string, options: IDecodeOptions): Promise<unknown> => {
  const extractOptions = (): VerifyOptions => {
    const decodeOptions = { ...options };
    delete decodeOptions.maxRetries;
    return decodeOptions;
  };
  return new Promise((resolve, reject) => {
    jwtVerify(token, key, extractOptions(), (err, decoded) => {
      if (err) {
        return reject(new JwtError('JsonWebTokenError', err.message));
      }
      return resolve(decoded);
    });
  });
};

const isIssuerValid = (issuer: string) => {
  return issuer.match(/https:\/\/cognito-idp.[a-z1-9-]+.amazonaws.com\/.+\/?/);
};

export const verify = async (token: string, options: IDecodeOptions): Promise<unknown> => {
  if (!token || typeof token !== 'string') {
    throw new JwtError('InvalidToken', 'Token provided must be a non-empty string');
  }
  if (!isIssuerValid(options.issuer)) {
    throw new JwtError('InvalidIssuer', 'Issuer must match https:\\/\\/cognito-idp.[a-z1-9-]+.amazonaws.com\\/.+\\/?');
  }
  const decoded = decode(token, { complete: true });
  if (!decoded) {
    throw new JwtError(
      'TokenNotDecoded',
      'An error occurred decoding you JWT. Check that your token is a well-formed JWT',
    );
  }
  const kid = decoded.header.kid;
  if (!kid) {
    throw new JwtError('MissingKeyID', 'The given JWT has no kid. Please double-check it is a valid token.');
  }

  const key = await buildKey(options, kid);
  return verifyJWT(token, key, options);
};
