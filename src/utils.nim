import std/[json, times, os]

type
    TokenInfo* = object
        ## Token information structure for managing OAuth2 tokens.
        accessToken*: string
        refreshToken*: string
        expiresIn*: int
        timestamp*: Time

proc loadTokens*(tokenFilePath: string): TokenInfo =
    ## Load tokens from a JSON file.
    ## Expected JSON structure: {"access_token": "...", "refresh_token": "...", "expires_in": 3600, "timestamp": "..."}
    ## Raises IOError if the file doesn't exist, and ValueError if the JSON structure is invalid.
    if not fileExists(tokenFilePath):
        raise newException(IOError, "Token file not found: " & tokenFilePath)
    
    let jsonData = parseFile(tokenFilePath)
    result.accessToken = jsonData["access_token"].getStr()
    result.refreshToken = jsonData["refresh_token"].getStr()
    result.expiresIn = jsonData["expires_in"].getInt()
    
    let timestampStr = jsonData["timestamp"].getStr()
    result.timestamp = parse(timestampStr, "yyyy-MM-dd'T'HH:mm:sszzz").toTime()

proc saveTokens*(tokenFilePath: string, accessToken, refreshToken: string, expiresIn: int) =
    ## Save tokens to a JSON file with current timestamp.
    ## Creates the file if it doesn't exist, overwrites if it does.
    var jsonData = %*{
        "access_token": accessToken,
        "refresh_token": refreshToken,
        "expires_in": expiresIn,
        "timestamp": $getTime()
    }
    writeFile(tokenFilePath, jsonData.pretty(2))

proc updateTokens*(tokenFilePath: string, accessToken: string, expiresIn: int, refreshToken: string = "") =
    ## Update access token in token file, optionally updating refresh token too.
    ## Updates the timestamp to the current time.
    ## Raises IOError if the file doesn't exist.
    if not fileExists(tokenFilePath):
        raise newException(IOError, "Token file not found: " & tokenFilePath)
    
    let jsonData = parseFile(tokenFilePath)
    jsonData["access_token"] = %accessToken
    jsonData["expires_in"] = %expiresIn
    jsonData["timestamp"] = %($getTime())
    if refreshToken.len > 0:
        jsonData["refresh_token"] = %refreshToken
    writeFile(tokenFilePath, jsonData.pretty(2))

proc isTokenExpired*(tokenInfo: TokenInfo, bufferSeconds: int = 60): bool =
    ## Check if token is expired (with optional buffer before expiration).
    ## The buffer allows refreshing tokens before they actually expire.
    ## Default buffer is 60 seconds.
    let elapsed = (getTime() - tokenInfo.timestamp).inSeconds
    result = elapsed >= (tokenInfo.expiresIn - bufferSeconds)
