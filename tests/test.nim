# Put all tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (make sure the name starts with the letter 't').
# To run these tests, simply execute `nimble test` from the root directory.

import std/[unittest, uri, strutils, httpclient, os, json, times]
import oauth2

test "generateState generates 32 character string":
  let state = generateState()
  check state.len == 32

test "generateState generates different values":
  let state1 = generateState()
  let state2 = generateState()
  # Very unlikely to be the same with cryptographically secure randomness
  check state1 != state2

test "generatePKCE generates code verifier and challenge":
  let (codeVerifier, codeChallenge) = generatePKCE()
  check codeVerifier.len >= 43
  check codeVerifier.len <= 128
  check codeChallenge.len > 0
  # Code verifier should contain only URL-safe characters
  for c in codeVerifier:
    check c in {'A'..'Z', 'a'..'z', '0'..'9', '-', '.', '_', '~'}
  # Code challenge should be base64url encoded (no padding, no + or /)
  check '=' notin codeChallenge
  check '+' notin codeChallenge
  check '/' notin codeChallenge

test "generatePKCE generates different values":
  let pkce1 = generatePKCE()
  let pkce2 = generatePKCE()
  # Very unlikely to be the same with cryptographically secure randomness
  check pkce1.codeVerifier != pkce2.codeVerifier
  check pkce1.codeChallenge != pkce2.codeChallenge

test "get basic authorization header":
  let header = getBasicAuthorizationHeader("Aladdin", "open sesame")
  check header["Authorization"] == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="

test "get bearer request header":
  let header = getBearerRequestHeader("Aladdin")
  check header["Authorization"] == "Bearer Aladdin"

test "getBearerRequestHeader returns non-nil headers":
  let header = getBearerRequestHeader("test_token_123")
  check header != nil

test "getBasicAuthorizationHeader returns non-nil headers":
  let header = getBasicAuthorizationHeader("client_id", "client_secret")
  check header != nil

test "authorization code grant url":
  const
    url = "http://server.example.com/authorize"
    clientId = "s6BhdRkqt3"
    redirectUri = "https://client.example.com/cb"
    state = "xyz"
  let correct = "http://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb"
  check(getAuthorizationCodeGrantUrl(url, clientId, redirectUri, state) == correct)

test "authorization code grant url with PKCE":
  const
    url = "http://server.example.com/authorize"
    clientId = "s6BhdRkqt3"
    redirectUri = "https://client.example.com/cb"
    state = "xyz"
    codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  let authUrl = getAuthorizationCodeGrantUrl(url, clientId, redirectUri, state, codeChallenge = codeChallenge)
  check "code_challenge=" in authUrl
  check "code_challenge_method=S256" in authUrl
  check codeChallenge in authUrl

test "getAuthorizationCodeGrantUrl includes required parameters":
  let url = getAuthorizationCodeGrantUrl("https://example.com/auth", "my_client_id", 
                                         redirectUri = "http://localhost:8080", 
                                         state = "test_state")
  check "response_type=code" in url
  check "client_id=" in url
  check "redirect_uri=" in url
  check "state=" in url

test "parse redirect uri":
  let
    uri = "https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz"
    response = parseAuthorizationResponse(uri)
  check response.code == "SplxlOBeZQQYbYS6WxSbIA"
  check response.state == "xyz"

test "parseAuthorizationResponse parses valid code response":
  let uri = parseUri("http://localhost:8080?code=abc123&state=xyz789")
  let response = parseAuthorizationResponse(uri)
  check response.code == "abc123"
  check response.state == "xyz789"

test "parse redirect uri with error":
  let uri = "https://client.example.com/cb?error=access_denied&state=xyz"
  var raised = false
  try:
    discard parseAuthorizationResponse(uri)
  except AuthorizationError as error:
    raised = true
    check error.error == "access_denied"
    check error.state == "xyz"
  check raised == true

test "parse redirect uri with full error details":
  let uri = "https://client.example.com/cb?error=access_denied&error_description=error%20description&error_uri=http%3A%2F%2Fexample.com&state=xyz"
  var raised = false
  try:
    discard parseAuthorizationResponse(uri)
  except AuthorizationError as error:
    raised = true
    check error.error == "access_denied"
    check error.errorDescription == "error description"
    check error.errorUri == "http://example.com"
    check error.state == "xyz"
  check raised == true

test "saveTokens creates token file with correct structure":
  let testFile = "test_tokens.json"
  defer: removeFile(testFile)
  
  saveTokens(testFile, "test_access_token", "test_refresh_token", 3600)
  check fileExists(testFile)
  
  let jsonData = parseFile(testFile)
  check jsonData["access_token"].getStr() == "test_access_token"
  check jsonData["refresh_token"].getStr() == "test_refresh_token"
  check jsonData["expires_in"].getInt() == 3600
  check jsonData.hasKey("timestamp")

test "loadTokens loads token file correctly":
  let testFile = "test_tokens_load.json"
  defer: removeFile(testFile)
  
  # Create a test token file
  let testTime = getTime()
  var jsonData = %*{
    "access_token": "loaded_access_token",
    "refresh_token": "loaded_refresh_token",
    "expires_in": 7200,
    "timestamp": $testTime
  }
  writeFile(testFile, jsonData.pretty(2))
  
  let tokenInfo = loadTokens(testFile)
  check tokenInfo.accessToken == "loaded_access_token"
  check tokenInfo.refreshToken == "loaded_refresh_token"
  check tokenInfo.expiresIn == 7200

test "loadTokens raises IOError for non-existent file":
  var raised = false
  try:
    discard loadTokens("non_existent_file.json")
  except IOError:
    raised = true
  check raised == true

test "updateTokens updates access token and timestamp":
  let testFile = "test_tokens_update.json"
  defer: removeFile(testFile)
  
  # Create initial token file
  saveTokens(testFile, "old_access_token", "refresh_token", 3600)
  let initialTokens = loadTokens(testFile)
  let initialTimestamp = initialTokens.timestamp
  
  # Small delay to ensure timestamp difference
  sleep(1100)  # Sleep for 1.1 seconds to ensure timestamp difference
  
  updateTokens(testFile, "new_access_token", 1800)
  
  let tokenInfo = loadTokens(testFile)
  check tokenInfo.accessToken == "new_access_token"
  check tokenInfo.expiresIn == 1800
  check tokenInfo.refreshToken == "refresh_token"  # Should remain unchanged
  check tokenInfo.timestamp > initialTimestamp  # Timestamp should be updated

test "updateTokens updates refresh token when provided":
  let testFile = "test_tokens_update_refresh.json"
  defer: removeFile(testFile)
  
  saveTokens(testFile, "old_access_token", "old_refresh_token", 3600)
  updateTokens(testFile, "new_access_token", 1800, "new_refresh_token")
  
  let tokenInfo = loadTokens(testFile)
  check tokenInfo.accessToken == "new_access_token"
  check tokenInfo.refreshToken == "new_refresh_token"

test "updateTokens raises IOError for non-existent file":
  var raised = false
  try:
    updateTokens("non_existent_file.json", "token", 3600)
  except IOError:
    raised = true
  check raised == true

test "isTokenExpired returns false for valid token":
  let tokenInfo = TokenInfo(
    accessToken: "token",
    refreshToken: "refresh",
    expiresIn: 3600,
    timestamp: getTime()
  )
  check isTokenExpired(tokenInfo, bufferSeconds = 60) == false

test "isTokenExpired returns true for expired token":
  let pastTime = getTime() - initDuration(seconds = 3700)  # 3700 seconds ago
  let tokenInfo = TokenInfo(
    accessToken: "token",
    refreshToken: "refresh",
    expiresIn: 3600,  # Expires in 3600 seconds
    timestamp: pastTime
  )
  check isTokenExpired(tokenInfo, bufferSeconds = 60) == true

test "isTokenExpired respects buffer seconds":
  let pastTime = getTime() - initDuration(seconds = 3550)  # 3550 seconds ago
  let tokenInfo = TokenInfo(
    accessToken: "token",
    refreshToken: "refresh",
    expiresIn: 3600,
    timestamp: pastTime
  )
  # Token expires in 50 seconds, but buffer is 60, so it should be considered expired
  check isTokenExpired(tokenInfo, bufferSeconds = 60) == true
  # With smaller buffer, it should not be expired yet
  check isTokenExpired(tokenInfo, bufferSeconds = 40) == false

test "saveTokens and loadTokens round-trip correctly":
  let testFile = "test_tokens_roundtrip.json"
  defer: removeFile(testFile)
  
  saveTokens(testFile, "roundtrip_access", "roundtrip_refresh", 5400)
  let loaded = loadTokens(testFile)
  
  check loaded.accessToken == "roundtrip_access"
  check loaded.refreshToken == "roundtrip_refresh"
  check loaded.expiresIn == 5400