import std/[uri, base64, sysrand, strtabs, strutils, asynchttpserver,
            asyncdispatch, asyncnet, httpclient, browsers]
import pkg/checksums/sha2
import utils
export utils

{.warning[ImplicitDefaultValue]:off.} # disables warning for implicit default value in proc parameters

type
    GrantType = enum
        AuthorizationCode = "authorization_code",
        ResourceOwnerPassCreds = "password",
        ClientCreds = "client_credentials",
        RefreshToken = "refresh_token"

    AuthorizationResponse* = ref object
        code*, state*: string

    AuthorizationError* = object of CatchableError
        error*, errorDescription*, errorUri*, state*: string

    RedirectUriParseError* = object of CatchableError

const UrlSafeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

proc setRequestHeaders(headers: HttpHeaders, body: string) =
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["Content-Length"] = $len(body)

proc getGrantUrl(url, clientId: string, grantType: GrantType,
    redirectUri, state: string, scope: openarray[string] = [], accessType: string,
    codeChallenge: string = ""): string =
    var url = url
    let parsed = parseUri(url)
    url = url & (if parsed.query == "": "?" else: "&")
    url = url & "response_type=code" &
      "&client_id=" & encodeUrl(clientId) & "&state=" & encodeUrl(state)
    if len(redirectUri) > 0:
        url = url & "&redirect_uri=" & encodeUrl(redirectUri)
    if len(scope) > 0:
        url = url & "&scope=" & encodeUrl(scope.join(" "))
    if len(accessType) > 0:
        url = url & "&access_type=" & encodeUrl(accessType)
    if len(codeChallenge) > 0:
        url = url & "&code_challenge=" & encodeUrl(codeChallenge) & "&code_challenge_method=S256"
    result = url

proc getAuthorizationCodeGrantUrl*(url, clientId: string;
    redirectUri: string = "", state: string = ""; scope: openarray[string] = [],
    accessType: string = "", codeChallenge: string = ""): string =
    ## Returns the URL for sending authorization requests in "Authorization Code Grant" type.
    ## If codeChallenge is provided, PKCE will be used (RFC 7636).
    result = getGrantUrl(url, clientId, AuthorizationCode, redirectUri, state, scope, accessType, codeChallenge)

proc getBasicAuthorizationHeader*(clientId, clientSecret: string): HttpHeaders =
    ## Returns a header necessary to basic authentication.
    var auth = encode(clientId & ":" & clientSecret)
    auth = auth.replace("\c\L", "")
    result = newHttpHeaders({"Authorization": "Basic " & auth})

proc getBasicAuthorizationHeader(clientId, clientSecret, body: string): HttpHeaders =
    result = getBasicAuthorizationHeader(clientId, clientSecret)
    result.setRequestHeaders(body)

proc getBearerRequestHeader*(accessToken: string): HttpHeaders =
    ## Returns a header necessary to bearer request.
    result = newHttpHeaders({"Authorization": "Bearer " & accessToken})

proc getBearerRequestHeader(accessToken: string,
    extraHeaders: HttpHeaders, body: string): HttpHeaders =
    result = getBearerRequestHeader(accessToken)
    result.setRequestHeaders(body)
    if extraHeaders != nil:
      for k, v in pairs(extraHeaders):
        result[k] = v

proc accessTokenRequest(client: HttpClient | AsyncHttpClient,
    url, clientId, clientSecret: string;
    grantType: GrantType, useBasicAuth: bool;
    code, redirectUri, username, password, refreshToken = "",
    scope: seq[string] = @[], codeVerifier: string = ""): Future[Response | AsyncResponse] {.multisync.} =
    var body = "grant_type=" & $grantType
    case grantType
    of ResourceOwnerPassCreds:
        body = body & "&username=" & encodeUrl(username) & "&password=" & encodeUrl(password)
        if len(scope) > 0:
            body = body & "&scope=" & encodeUrl(scope.join(" "))
    of AuthorizationCode:
        body = body & "&code=" & encodeUrl(code)
        if len(redirectUri) > 0:
            body = body & "&redirect_uri=" & encodeUrl(redirectUri)
        if len(codeVerifier) > 0:
            body = body & "&code_verifier=" & encodeUrl(codeVerifier)
    of ClientCreds:
        if len(scope) > 0:
            body = body & "&scope=" & encodeUrl(scope.join(" "))
    of RefreshToken:
        body = body & "&refresh_token=" & encodeUrl(refreshToken)
        if len(scope) > 0:
            body = body & "&scope=" & encodeUrl(scope.join(" "))

    var header: HttpHeaders
    if useBasicAuth:
        header = getBasicAuthorizationHeader(clientId, clientSecret, body)
    else:
        body = body & "&client_id=" & encodeUrl(clientId) & "&client_secret=" & encodeUrl(clientSecret)
        header = newHttpHeaders()
        header.setRequestHeaders(body)

    result = await client.request(url, httpMethod = HttpPOST, headers = header, body = body)

proc getAuthorizationCodeAccessToken*(client: HttpClient | AsyncHttpClient,
    url, code, clientId, clientSecret: string,
    redirectUri: string = "", useBasicAuth: bool = true, codeVerifier: string = ""): Future[Response | AsyncResponse] {.multisync.}=
    ## Send the access token request for "Authorization Code Grant" type.
    ## If codeVerifier is provided, PKCE will be used (RFC 7636).
    result = await client.accessTokenRequest(url, clientId, clientSecret,
        AuthorizationCode, useBasicAuth, code, redirectUri, codeVerifier = codeVerifier)

# ref. https://github.com/nim-lang/Nim/blob/master/lib/pure/asynchttpserver.nim#L154
proc getCallbackParameters(port: Port, html: string): Future[Uri] {.async.} =
    let socket = newAsyncSocket()
    socket.bindAddr(port)
    socket.listen()

    proc processClient(client: AsyncSocket): Future[string] {.async.} =
        var request = Request()
        request.headers = newHttpHeaders()
        result = ""
        while not client.isClosed:
            doAssert client != nil
            request.client = client
            var line = await client.recvLine()
            if line == "":
                client.close()
            else:
                var url = line.split(" ")[1]
                request.url = parseUri url
                while true:
                    line = await client.recvLine()
                    if line == "\c\L":
                        break
                    let fd = line.find(":")
                    request.headers[line[0..fd-1].strip()] = line[fd+1..len(line)-1].strip()
                await request.respond(Http200, html)
                result = url
                client.close()
    var url: string
    while true:
        var fut = await socket.acceptAddr()
        url = await processClient(fut.client)
        if len(url) > 0:
            break
    result = parseUri url

proc generateState*(): string =
    ## Generate a cryptographically secure state parameter for OAuth2 flows.
    result = newString(32)
    let randomBytes = urandom(32)
    for i in 0..31:
        result[i] = UrlSafeChars[int(randomBytes[i]) mod UrlSafeChars.len]

proc generatePKCE*(): tuple[codeVerifier: string, codeChallenge: string] =
    ## Generate PKCE code verifier and challenge.
    ## Returns a tuple with code_verifier and code_challenge (base64url-encoded SHA256 hash).
    ## The code_verifier is a cryptographically random string of 43-128 characters.
    # Generate 43-128 characters, using 64 for good security/performance balance
    # Use urandom for cryptographically secure randomness
    var codeVerifier = newString(64)
    let randomBytes = urandom(64)
    for i in 0..63:
        codeVerifier[i] = UrlSafeChars[int(randomBytes[i]) mod UrlSafeChars.len]
    
    # Compute SHA256 hash and base64url encode
    var hasher = initSha_256()
    hasher.update(codeVerifier)
    let digest = hasher.digest()
    var codeChallenge = encode(digest, safe = true)
    # Remove padding (RFC 4648 Section 3.2 - base64url omits padding)
    codeChallenge = codeChallenge.replace("=", "")
    
    result = (codeVerifier: codeVerifier, codeChallenge: codeChallenge)

proc parseRedirectUri(body: string): StringTableRef =
    let responses = body.split("&")
    result = newStringTable(modeCaseInsensitive)
    for response in responses:
        if response.len == 0:
            continue
        let fd = response.find("=")
        if fd > 0 and fd < response.len - 1:
            let key = response[0..fd-1]
            let value = decodeUrl(response[fd+1..^1])
            result[key] = value
        elif fd > 0:
            # Handle case where value is empty (key=)
            let key = response[0..fd-1]
            result[key] = ""

proc parseAuthorizationResponse*(uri: Uri): AuthorizationResponse =
    ## Parse an authorization response of "Authorization Code Grant" added to redirect uri.
    let
        query = uri.query
        parsed = parseRedirectUri(query)
    if parsed.hasKey("code"):
        return AuthorizationResponse(code: parsed["code"], state: parsed["state"])
    if parsed.hasKey("error"):
        var error: ref AuthorizationError
        new(error)
        error.error = parsed["error"]
        if parsed.hasKey("error_description"):
            error.errorDescription = decodeUrl(parsed["error_description"])
        if parsed.hasKey("error_uri"):
            error.errorUri = decodeUrl(parsed["error_uri"])
        error.state = parsed["state"]
        raise error
    raise newException(RedirectUriParseError, "Failed to parse a redirect uri.")

proc parseAuthorizationResponse*(uri: string): AuthorizationResponse =
    uri.parseUri().parseAuthorizationResponse()

proc authorizationCodeGrant*(client: HttpClient | AsyncHttpClient,
    authorizeUrl, accessTokenRequestUrl, clientId, clientSecret: string,
    html: string = "", scope: seq[string] = @[],
    port: int = 8080, usePKCE: bool = false): Future[Response | AsyncResponse] {.multisync.} =
    ## Send a request for "Authorization Code Grant" type.
    ## | This method, outputs a URL for the authorization request at first.
    ## | Then, wait for the callback at "http://localhost:${port}".
    ## | When receiving the callback, check the state, and request an access token to the server.
    ## | Returns the request result of the access token.
    ## | If usePKCE is true, PKCE (RFC 7636) will be used for enhanced security.
    let
        state = generateState()
        redirectUri = "http://localhost:" & $port
        pkce = if usePKCE: generatePKCE() else: (codeVerifier: "", codeChallenge: "")
        authUrl = getAuthorizationCodeGrantUrl(authorizeUrl, clientId, redirectUri, state, scope, 
                                                codeChallenge = pkce.codeChallenge)

    openDefaultBrowser(authUrl)
    let
        uri = waitFor getCallbackParameters(Port(port), html)
        params = parseRedirectUri(uri.query)
    if not params.hasKey("state") or params["state"] != state:
        var error: ref AuthorizationError
        new(error)
        error.msg = "State mismatch in authorization response"
        error.error = "invalid_state"
        error.state = if params.hasKey("state"): params["state"] else: ""
        raise error
    if not params.hasKey("code"):
        raise newException(RedirectUriParseError, "Missing authorization code in redirect URI")
    result = await client.getAuthorizationCodeAccessToken(accessTokenRequestUrl, params["code"],
        clientId, clientSecret, redirectUri, codeVerifier = pkce.codeVerifier)


proc resourceOwnerPassCredsGrant*(client: HttpClient | AsyncHttpClient,
    url, clientId, clientSecret, username, password: string,
    scope: seq[string] = @[],
    useBasicAuth: bool = true): Future[Response | AsyncResponse] {.multisync.} =
    ## Send a request for "Resource Owner Password Credentials Grant" type.
    ##
    ##  | The client MUST discard the credentials once an access token has been obtained.
    ##  | -- https://tools.ietf.org/html/rfc6749#section-4.3
    result = await client.accessTokenRequest(url, clientId, clientSecret, ResourceOwnerPassCreds,
        useBasicAuth, username = username, password = password, scope = scope)

proc clientCredsGrant*(client: HttpClient | AsyncHttpClient,
    url, clientId, clientSecret: string,
    scope: seq[string] = @[],
    useBasicAuth: bool = true): Future[Response | AsyncResponse] {.multisync.} =
    ## Send a request for "Client Credentials Grant" type.
    result = await client.accessTokenRequest(url, clientId, clientSecret, ClientCreds,
        useBasicAuth, scope = scope)

proc refreshToken*(client: HttpClient | AsyncHttpClient,
    url, clientId, clientSecret, refreshToken: string,
    scope: seq[string] = @[],
    useBasicAuth: bool = true): Future[Response | AsyncResponse] {.multisync.} =
    ## Send an update request of the access token.
    result = await client.accessTokenRequest(url, clientId, clientSecret, RefreshToken,
        useBasicAuth, refreshToken = refreshToken, scope = scope)

proc bearerRequest*(client: HttpClient | AsyncHttpClient,
    url, accessToken: string, httpMethod = HttpGET,
    extraHeaders: HttpHeaders = nil,
    body = ""): Future[Response | AsyncResponse] {.multisync.} =
    ## Send a request using the bearer token.
    let header = getBearerRequestHeader(accessToken, extraHeaders, body)
    result = await client.request(url, httpMethod = httpMethod, headers = header, body = body)
