# oauth2

A comprehensive OAuth2 library for Nim with support for multiple grant types, PKCE (RFC 7636), and token management utilities.

## Overview

This library provides a complete implementation of the OAuth2 authorization framework for Nim applications. It supports all major OAuth2 grant types and includes enhanced security features like PKCE (Proof Key for Code Exchange) for public clients.

**Built upon [CORDEA/oauth](https://github.com/CORDEA/oauth) with several improvements:**
- Enhanced PKCE support with secure code verifier/challenge generation
- Comprehensive token management utilities (save, load, update, expiration checking)
- More robust URL parsing and parameter handling

## Features

- **Authorization Code Grant** - The most common OAuth2 flow for web applications
- **Resource Owner Password Credentials Grant** - For trusted applications
- **Client Credentials Grant** - For server-to-server authentication
- **Refresh Token** - Automatic token refresh support
- **PKCE (RFC 7636)** - Enhanced security for public clients
- **Token Management** - Save, load, and manage tokens with expiration checking
- **Bearer Token Requests** - Easy API calls with bearer authentication
- **Async/Sync Support** - Works with both synchronous and asynchronous HTTP clients via `{.multisync.}`
- **State Validation** - Cryptographically secure state parameter generation and validation

## Installation

Since this package is not yet published on Nimble, you can install it directly from GitHub:

```bash
nimble install https://github.com/Niminem/OAuth2.git
```

Alternatively, you can clone the repository and install:

```bash
git clone https://github.com/Niminem/OAuth2.git
cd OAuth2
nimble install
```

## Requirements

- Nim >= 2.2.4
- `checksums` package (for PKCE SHA256 hashing)

## Quick Start

### Authorization Code Grant (with PKCE)

```nim
import oauth2
import std/[httpclient, json]

# Configure your OAuth2 provider
const
  authorizeUrl = "https://example.com/oauth/authorize"
  tokenUrl = "https://example.com/oauth/token"
  clientId = "your_client_id"
  clientSecret = "your_client_secret"

# Use the authorization code grant with PKCE
let client = newHttpClient()
let response = client.authorizationCodeGrant(
  authorizeUrl,
  tokenUrl,
  clientId,
  clientSecret,
  scope = @["read", "write"],
  usePKCE = true  # Enable PKCE for enhanced security
)

# Parse the token response
let tokenData = parseJson(response.body)
let accessToken = tokenData["access_token"].getStr()
let refreshToken = tokenData["refresh_token"].getStr()
let expiresIn = tokenData["expires_in"].getInt()

# Save tokens for later use
saveTokens("tokens.json", accessToken, refreshToken, expiresIn)
```

### Manual Authorization Flow

If you need more control over the authorization flow:

```nim
import oauth2
import std/[httpclient, browsers]

# Configure your OAuth2 provider
const
  authorizeUrl = "https://example.com/oauth/authorize"
  tokenUrl = "https://example.com/oauth/token"
  clientId = "your_client_id"
  clientSecret = "your_client_secret"

let client = newHttpClient()

# Generate state and PKCE parameters
let state = generateState()
let (codeVerifier, codeChallenge) = generatePKCE()

# Build authorization URL
let authUrl = getAuthorizationCodeGrantUrl(
  authorizeUrl,
  clientId,
  redirectUri = "http://localhost:8080",
  state = state,
  scope = @["read", "write"],
  codeChallenge = codeChallenge
)

# Open browser for user authorization
openDefaultBrowser(authUrl)

# After user authorizes, parse the callback
let callbackUri = "http://localhost:8080?code=abc123&state=" & state
let authResponse = parseAuthorizationResponse(callbackUri)

# Exchange code for access token
let response = client.getAuthorizationCodeAccessToken(
  tokenUrl,
  authResponse.code,
  clientId,
  clientSecret,
  redirectUri = "http://localhost:8080",
  codeVerifier = codeVerifier
)
```

### Client Credentials Grant

For server-to-server authentication:

```nim
import oauth2
import std/httpclient

let client = newHttpClient()
let response = client.clientCredsGrant(
  "https://example.com/oauth/token",
  clientId,
  clientSecret,
  scope = @["api:read"]
)

let tokenData = parseJson(response.body)
let accessToken = tokenData["access_token"].getStr()
```

### Resource Owner Password Credentials Grant

For trusted applications (use with caution):

```nim
import oauth2
import std/httpclient

let client = newHttpClient()
let response = client.resourceOwnerPassCredsGrant(
  "https://example.com/oauth/token",
  clientId,
  clientSecret,
  username = "user@example.com",
  password = "password",
  scope = @["read", "write"]
)
```

### Refresh Token

Refresh an expired access token:

```nim
import oauth2
import std/httpclient

let client = newHttpClient()

# Load existing tokens
let tokenInfo = loadTokens("tokens.json")

# Check if token is expired
if isTokenExpired(tokenInfo):
  # Refresh the token
  let response = client.refreshToken(
    "https://example.com/oauth/token",
    clientId,
    clientSecret,
    tokenInfo.refreshToken
  )
  
  let tokenData = parseJson(response.body)
  updateTokens(
    "tokens.json",
    tokenData["access_token"].getStr(),
    tokenData["expires_in"].getInt(),
    tokenData["refresh_token"].getStr()
  )
```

### Making Authenticated API Requests

Use bearer tokens to make authenticated requests:

```nim
import oauth2
import std/httpclient

let client = newHttpClient()
let tokenInfo = loadTokens("tokens.json")

# Make a GET request
let response = client.bearerRequest(
  "https://api.example.com/user",
  tokenInfo.accessToken
)

# Make a POST request with body
let postResponse = client.bearerRequest(
  "https://api.example.com/data",
  tokenInfo.accessToken,
  httpMethod = HttpPOST,
  body = """{"key": "value"}"""
)
```

## API Reference

### Authorization Code Grant

#### `authorizationCodeGrant`
Complete authorization code grant flow with automatic browser opening and callback handling.

```nim
proc authorizationCodeGrant(
  client: HttpClient | AsyncHttpClient,
  authorizeUrl, accessTokenRequestUrl, clientId, clientSecret: string,
  html: string = "",
  scope: seq[string] = @[],
  port: int = 8080,
  usePKCE: bool = false
): Future[Response | AsyncResponse]
```

#### `getAuthorizationCodeGrantUrl`
Generate the authorization URL for the authorization code grant.

```nim
proc getAuthorizationCodeGrantUrl*(
  url, clientId: string;
  redirectUri: string = "";
  state: string = "";
  scope: openarray[string] = [];
  accessType: string = "";
  codeChallenge: string = ""
): string
```

#### `getAuthorizationCodeAccessToken`
Exchange an authorization code for an access token.

```nim
proc getAuthorizationCodeAccessToken*(
  client: HttpClient | AsyncHttpClient,
  url, code, clientId, clientSecret: string,
  redirectUri: string = "",
  useBasicAuth: bool = true,
  codeVerifier: string = ""
): Future[Response | AsyncResponse]
```

### Other Grant Types

#### `clientCredsGrant`
Client credentials grant for server-to-server authentication.

```nim
proc clientCredsGrant*(
  client: HttpClient | AsyncHttpClient,
  url, clientId, clientSecret: string,
  scope: seq[string] = @[],
  useBasicAuth: bool = true
): Future[Response | AsyncResponse]
```

#### `resourceOwnerPassCredsGrant`
Resource owner password credentials grant (use with caution).

```nim
proc resourceOwnerPassCredsGrant*(
  client: HttpClient | AsyncHttpClient,
  url, clientId, clientSecret, username, password: string,
  scope: seq[string] = @[],
  useBasicAuth: bool = true
): Future[Response | AsyncResponse]
```

#### `refreshToken`
Refresh an access token using a refresh token.

```nim
proc refreshToken*(
  client: HttpClient | AsyncHttpClient,
  url, clientId, clientSecret, refreshToken: string,
  scope: seq[string] = @[],
  useBasicAuth: bool = true
): Future[Response | AsyncResponse]
```

### PKCE Support

#### `generatePKCE`
Generate PKCE code verifier and challenge pair.

```nim
proc generatePKCE*(): tuple[codeVerifier: string, codeChallenge: string]
```

Returns a tuple with:
- `codeVerifier`: A cryptographically random 64-character URL-safe string
- `codeChallenge`: Base64url-encoded SHA256 hash of the code verifier

#### `generateState`
Generate a cryptographically secure state parameter.

```nim
proc generateState*(): string
```

Returns a 32-character URL-safe random string.

### Token Management

#### `TokenInfo`
Structure for managing OAuth2 tokens.

```nim
type TokenInfo* = object
  accessToken*: string
  refreshToken*: string
  expiresIn*: int
  timestamp*: Time
```

#### `saveTokens`
Save tokens to a JSON file.

```nim
proc saveTokens*(
  tokenFilePath: string,
  accessToken, refreshToken: string,
  expiresIn: int
)
```

#### `loadTokens`
Load tokens from a JSON file.

```nim
proc loadTokens*(tokenFilePath: string): TokenInfo
```

#### `updateTokens`
Update access token in token file.

```nim
proc updateTokens*(
  tokenFilePath: string,
  accessToken: string,
  expiresIn: int,
  refreshToken: string = ""
)
```

#### `isTokenExpired`
Check if a token is expired (with optional buffer).

```nim
proc isTokenExpired*(
  tokenInfo: TokenInfo,
  bufferSeconds: int = 60
): bool
```

### Utility Functions

#### `getBasicAuthorizationHeader`
Generate Basic authentication header.

```nim
proc getBasicAuthorizationHeader*(
  clientId, clientSecret: string
): HttpHeaders
```

#### `getBearerRequestHeader`
Generate Bearer authentication header.

```nim
proc getBearerRequestHeader*(accessToken: string): HttpHeaders
```

#### `bearerRequest`
Make an authenticated request with bearer token.

```nim
proc bearerRequest*(
  client: HttpClient | AsyncHttpClient,
  url, accessToken: string,
  httpMethod = HttpGET,
  extraHeaders: HttpHeaders = nil,
  body = ""
): Future[Response | AsyncResponse]
```

#### `parseAuthorizationResponse`
Parse authorization response from redirect URI.

```nim
proc parseAuthorizationResponse*(uri: Uri): AuthorizationResponse
proc parseAuthorizationResponse*(uri: string): AuthorizationResponse
```

### Response Types

#### `AuthorizationResponse`
Structure representing an authorization response from the OAuth2 provider.

```nim
type AuthorizationResponse* = ref object
  code*, state*: string
```

Returns a reference object with:
- `code`: The authorization code returned by the provider
- `state`: The state parameter that was sent in the authorization request (for validation)

### Error Types

#### `AuthorizationError`
Raised when authorization fails.

```nim
type AuthorizationError* = object of CatchableError
  error*, errorDescription*, errorUri*, state*: string
```

#### `RedirectUriParseError`
Raised when redirect URI cannot be parsed.

```nim
type RedirectUriParseError* = object of CatchableError
```

## Examples

For now, see the `tests/test.nim` file for test cases demonstrating all features of the library.

## Security Considerations

1. **PKCE**: Always use PKCE (`usePKCE = true`) for public clients to prevent authorization code interception attacks.

2. **State Parameter**: Always validate the state parameter to prevent CSRF attacks. The library automatically generates and validates state when using `authorizationCodeGrant`.

3. **Token Storage**: Store tokens securely. The token management utilities save tokens in JSON format - consider encrypting sensitive token files in production.

4. **HTTPS**: Always use HTTPS for OAuth2 endpoints in production.

5. **Client Secrets**: Never expose client secrets in client-side code. Use Basic Authentication for token requests when possible.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.