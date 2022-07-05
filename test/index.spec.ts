import {JwtError, verify} from '../src';
import jwt from 'jsonwebtoken';
import * as convertToPem from 'jwk-to-pem';
import nock from "nock";

jest.mock('jsonwebtoken');
jest.mock('jwk-to-pem');

const mocks = {
  token: '$token',
  issuer: 'https://cognito-idp.region.amazonaws.com/poolId',
  kid: '$kid',
}

describe('The token verifier method', () => {
  let decode: jest.SpyInstance;
  let jwtVerify: jest.SpyInstance;
  let pem: jest.SpyInstance;
  beforeEach(() => {
    decode = jest.spyOn(jwt, 'decode');
    pem = jest.spyOn(convertToPem, 'default');
    jwtVerify = jest.spyOn(jwt, 'verify');
  });
  afterEach(() => {
    decode.mockRestore();
    pem.mockRestore();
    jwtVerify.mockRestore();
  })
  it('should throw InvalidToken if token if empty', async () => {
    try {
      await verify('', {
        issuer: mocks.issuer,
      });
      fail('should fail');
    } catch (e) {
      expect((e as JwtError).code).toBe('InvalidToken');
    }
  });
  it('should throw InvalidToken if token if not a string', async () => {
    try {
      await verify(42 as unknown as string, {
        issuer: mocks.issuer,
      });
      fail('should fail');
    } catch (e) {
      expect((e as JwtError).code).toBe('InvalidToken');
    }
  });
  it('should throw TokenNotDecoded if token is invalid', async () => {
    try {
      await verify('i am not valid base64 encoded token :P', {
        issuer: mocks.issuer,
      });
      fail('should fail');
    } catch (e) {
      expect((e as JwtError).code).toBe('TokenNotDecoded');
    }
  });
  it('should throw InvalidIssuer if issuer is invalid', async () => {
    decode.mockImplementation(() => ({ header: { kid: undefined } }));
    try {
      await verify('$token', {
        issuer: 'invalid',
      });
      fail('should fail');
    } catch (e) {
      expect((e as JwtError).code).toBe('InvalidIssuer');
    }
  });
  it('should throw MissingKeyID if kid is not specified in token header', async () => {
    decode.mockImplementation(() => ({ header: { kid: undefined } }));
    try {
      await verify('$token', {
        issuer: mocks.issuer,
      });
      fail('should fail');
    } catch (e) {
      expect(decode).toHaveBeenCalledTimes(1);
      expect(decode).toHaveBeenCalledWith('$token', { complete: true });
      expect((e as JwtError).code).toBe('MissingKeyID');
    }
  });
  it('should throw ErrorFetchingKeys if discovery url return 4xx status code', async () => {
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(400, 'Bad Request');
    decode.mockImplementation(() => ({ header: { kid: mocks.kid } }));
    try {
      await verify('$token', {
        issuer: mocks.issuer,
      });
      fail('should fail');
    } catch (e) {
      expect(decode).toHaveBeenCalledTimes(1);
      expect(decode).toHaveBeenCalledWith('$token', { complete: true });
      expect((e as JwtError).code).toBe('ErrorFetchingKeys');
    }
  });
  it('should throw ErrorFetchingKeys if discovery url call fails', async () => {
    nock(mocks.issuer).get('/.well-known/jwks.json').replyWithError('Badaboom');
    decode.mockImplementation(() => ({ header: { kid: mocks.kid } }));
    try {
      await verify('$token', {
        issuer: mocks.issuer,
      });
      fail('should fail');
    } catch (e) {
      expect(decode).toHaveBeenCalledTimes(1);
      expect(decode).toHaveBeenCalledWith('$token', { complete: true });
      expect((e as JwtError).code).toBe('ErrorFetchingKeys');
    }
  });
  it('should throw ErrorFetchingKeys if discovery url return 5xx status code and retry limit is reached', async () => {
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(502, 'Bad Gateway');
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(502, 'Bad Gateway');
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(502, 'Bad Gateway');
    decode.mockImplementation(() => ({ header: { kid: mocks.kid } }));
    try {
      await verify('$token', {
        issuer: mocks.issuer,
      });
      fail('should fail');
    } catch (e) {
      expect(decode).toHaveBeenCalledTimes(1);
      expect(decode).toHaveBeenCalledWith('$token', { complete: true });
      expect((e as JwtError).code).toBe('ErrorFetchingKeys');
    }
  });
  it('should throw InvalidDiscoveryResponse if response body does not contain valid JWK [not-parsable]', async () => {
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(200, 'Invalid payload');
    decode.mockImplementation(() => ({ header: { kid: mocks.kid } }));
    try {
      await verify('$token', {
        issuer: mocks.issuer,
        maxRetries: 0,
      });
      fail('should fail');
    } catch (e) {
      expect(decode).toHaveBeenCalledTimes(1);
      expect(decode).toHaveBeenCalledWith('$token', { complete: true });
      expect((e as JwtError).code).toBe('InvalidDiscoveryResponse');
    }
  });
  it('should throw InvalidDiscoveryResponse if response body does not contain valid JWK [invalid]', async () => {
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(200, []);
    decode.mockImplementation(() => ({ header: { kid: mocks.kid } }));
    try {
      await verify('$token', {
        issuer: mocks.issuer,
        maxRetries: 0,
      });
      fail('should fail');
    } catch (e) {
      expect(decode).toHaveBeenCalledTimes(1);
      expect(decode).toHaveBeenCalledWith('$token', { complete: true });
      expect((e as JwtError).code).toBe('InvalidDiscoveryResponse');
    }
  });
  it('should throw NotMatchingKey if a key matching kid of token header is not found in response body', async () => {
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(200, JSON.stringify({keys: [{ kid: 'another-key' }]}));
    decode.mockImplementation(() => ({ header: { kid: mocks.kid } }));
    try {
      await verify('$token', {
        issuer: mocks.issuer,
        maxRetries: 0,
      });
      fail('should fail');
    } catch (e) {
      expect(decode).toHaveBeenCalledTimes(1);
      expect(decode).toHaveBeenCalledWith('$token', { complete: true });
      expect((e as JwtError).code).toBe('NotMatchingKey');
    }
  });
  it('should throw CannotConvertFromJwkToPem if conversion from JWK to PEM of the matching key fails', async () => {
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(200, JSON.stringify({keys: [{ kid: mocks.kid }]}));
    decode.mockImplementation(() => ({ header: { kid: mocks.kid } }));
    pem.mockImplementation(() => {
      throw Error('PAF!')
    });
    try {
      await verify('$token', {
        issuer: mocks.issuer,
        maxRetries: 0,
      });
      fail('should fail');
    } catch (e) {
      expect(decode).toHaveBeenCalledTimes(1);
      expect(pem).toHaveBeenCalledTimes(1);
      expect(decode).toHaveBeenCalledWith('$token', { complete: true });
      expect(pem).toHaveBeenCalledWith({ kid: mocks.kid });
      expect((e as JwtError).code).toBe('CannotConvertFromJwkToPem');
    }
  });
  it('should throw JsonWebTokenError if token validation fails', async () => {
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(200, JSON.stringify({keys: [{ kid: mocks.kid }]}));
    decode.mockImplementation(() => ({ header: { kid: mocks.kid } }));
    pem.mockImplementation(() => ({ fake: 'key' }));
    jwtVerify.mockImplementation((_token, _key, _options, callback) => {
     callback('Invalid token', null);
    });
    try {
      await verify('$token', {
        issuer: mocks.issuer,
        maxRetries: 0,
      });
      fail('should fail');
    } catch (e) {
      expect(decode).toHaveBeenCalledTimes(1);
      expect(pem).toHaveBeenCalledTimes(1);
      expect(decode).toHaveBeenCalledWith('$token', { complete: true });
      expect(pem).toHaveBeenCalledWith({ kid: mocks.kid });
      expect(jwtVerify).toHaveBeenCalledTimes(1);
      expect(jwtVerify.mock.calls[0][0]).toBe('$token');
      expect(jwtVerify.mock.calls[0][1]).toEqual({"fake": "key"});
      expect(jwtVerify.mock.calls[0][2]).toEqual({"issuer": "https://cognito-idp.region.amazonaws.com/poolId"});
      expect((e as JwtError).code).toBe('JsonWebTokenError');
    }
  });
  it('should verify the token and return the payload otherwise (no retry)', async () => {
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(200, JSON.stringify({keys: [{ kid: mocks.kid }]}));
    decode.mockImplementation(() => ({ header: { kid: mocks.kid } }));
    pem.mockImplementation(() => ({ fake: 'key' }));
    jwtVerify.mockImplementation((_token, _key, _options, callback) => {
      callback(null, { principalId: 'John Doe'});
    });
    const decoded = await verify('$token', {
      issuer: mocks.issuer,
      maxRetries: 0,
    });
    expect(decoded).toEqual({ principalId: 'John Doe' });
    expect(decode).toHaveBeenCalledTimes(1);
    expect(pem).toHaveBeenCalledTimes(1);
    expect(decode).toHaveBeenCalledWith('$token', { complete: true });
    expect(pem).toHaveBeenCalledWith({ kid: mocks.kid });
    expect(jwtVerify).toHaveBeenCalledTimes(1);
    expect(jwtVerify.mock.calls[0][0]).toBe('$token');
    expect(jwtVerify.mock.calls[0][1]).toEqual({"fake": "key"});
    expect(jwtVerify.mock.calls[0][2]).toEqual({"issuer": "https://cognito-idp.region.amazonaws.com/poolId"});
  });
  it('should verify the token and return the payload otherwise (with retries)', async () => {
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(502, 'Bad Gateway');
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(502, 'Bad Gateway');
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(502, 'Bad Gateway');
    nock(mocks.issuer).get('/.well-known/jwks.json').reply(200, JSON.stringify({keys: [{ kid: mocks.kid }]}));
    decode.mockImplementation(() => ({ header: { kid: mocks.kid } }));
    pem.mockImplementation(() => ({ fake: 'key' }));
    jwtVerify.mockImplementation((_token, _key, _options, callback) => {
      callback(null, { principalId: 'John Doe'});
    });
    const decoded = await verify('$token', {
      issuer: mocks.issuer,
      maxRetries: 5,
    });
    expect(decoded).toEqual({ principalId: 'John Doe' });
    expect(decode).toHaveBeenCalledTimes(1);
    expect(pem).toHaveBeenCalledTimes(1);
    expect(decode).toHaveBeenCalledWith('$token', { complete: true });
    expect(pem).toHaveBeenCalledWith({ kid: mocks.kid });
    expect(jwtVerify).toHaveBeenCalledTimes(1);
    expect(jwtVerify.mock.calls[0][0]).toBe('$token');
    expect(jwtVerify.mock.calls[0][1]).toEqual({"fake": "key"});
    expect(jwtVerify.mock.calls[0][2]).toEqual({"issuer": "https://cognito-idp.region.amazonaws.com/poolId"});
  });
});
