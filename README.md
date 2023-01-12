# cognito-jwt-lite

![npm bundle size](https://img.shields.io/bundlephobia/minzip/cognito-jwt-lite)
![npm](https://img.shields.io/npm/dm/cognito-jwt-lite)
![Snyk Vulnerabilities for GitHub Repo](https://img.shields.io/snyk/vulnerabilities/github/MarioArnt/cognito-jwt-lite)

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/MarioArnt/cognito-jwt-lite/publish.yml)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_cognito-jwt-lite&metric=coverage)](https://sonarcloud.io/dashboard?id=MarioArnt_cognito-jwt-lite)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_cognito-jwt-lite&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=MarioArnt_cognito-jwt-lite)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_cognito-jwt-lite&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=MarioArnt_cognito-jwt-lite)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_cognito-jwt-lite&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=MarioArnt_cognito-jwt-lite)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_cognito-jwt-lite&metric=security_rating)](https://sonarcloud.io/dashboard?id=MarioArnt_cognito-jwt-lite)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_cognito-jwt-lite&metric=sqale_index)](https://sonarcloud.io/dashboard?id=MarioArnt_cognito-jwt-lite)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_cognito-jwt-lite&metric=bugs)](https://sonarcloud.io/dashboard?id=MarioArnt_cognito-jwt-lite)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_cognito-jwt-lite&metric=code_smells)](https://sonarcloud.io/dashboard?id=MarioArnt_cognito-jwt-lite)

<p align="center">
  <img src="https://github.com/MarioArnt/cognito-jwt-lite/blob/main/logo.png?raw=true" alt="Logo"/>
</p>

Lightweight library to verify AWS Cognito JSON Web Tokens.

This package is implemented in typescript and provide its own type definitions.

## Getting started

Install the package using yarn or NPM: `npm i cognito-jwt-lite`

Do not forget to install dependent types definitions as dev dependency if you are using Typescript: `npm i -D @types/jsonwebtoken @types/jwk-to-pem`.

In your authentication middleware decode and verify the token using:

```typescript
import { verify } from 'cognito-jwt-lite';

const decoded = await verifyAzureToken(token, {
  issuer: `https://cognito-idp.${process.env.AWS_COGNITO_POOL_REGION}.amazonaws.com/${process.env.AWS_COGNITO_POOL_ID}`,
});
```

You can add any option supported by [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken):

```typescript
import { verify } from 'cognito-jwt-lite';

const decoded = await verifyAzureToken(token, {
  audience: process.env.JWT_AUD,
  issuer: `https://cognito-idp.${process.env.AWS_COGNITO_POOL_REGION}.amazonaws.com/${process.env.AWS_COGNITO_POOL_ID}`,
});
```

## Additional options

* Retries on 5xx: set the number of retries when request to fetch keys returns a 5xx response (defaults to 2)

```typescript
import { verifyAzureToken } from 'cognito-jwt-lite';

const decoded = await verifyAzureToken(token, {
  maxRetries: 5,
  audience: process.env.JWT_AUD,
  issuer: process.env.JWT_ISS,
});
```

## Error reference

The lib will throw the following errors if something wrong happends during decoding token:

 * `InvalidToken`: the token provided is not a non-empty string.
 * `InvalidIssuer`: the issuer does not match the pattern `https://cognito-idp.<aws-region>.amazonaws.com/<pool-id>`
 * `TokenNotDecoded`: the token cannot be decoded. This usually means the token is ill-formed.
 * `MissingKeyID`: no `kid` (Microsoft Key ID) field is present in JWT header.
 * `ErrorFetchingKeys`: API call to fetch Microsoft public keys failed.
 * `NotMatchingKey`: no matching key is found in Microsoft response.
 * `JsonWebTokenError`: token cannot be verified, the human-readable reason is provided (expired, audience mismatch etc...)
