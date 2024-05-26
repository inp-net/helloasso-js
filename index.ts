// import fetch, { RequestInit, Response } from "node-fetch"
import { URLSearchParams } from "url"
// import { Client } from "oauth2"
// import * as OAuth2 from "oauth2"

class OAuth2Api {
  private apiBase: string
  private clientId: string
  private clientSecret: string
  private timeout: number
  private _accessToken: string | undefined
  private _refreshToken: string | undefined
  private oauth2TokenGetter: OAuth2TokenGetter | undefined
  private oauth2TokenSetter: OAuth2TokenSetter | undefined
  //   private client: OAuth2.Client
  //   private auth: string
  private log: ReturnType<Logger>

  constructor(params: {
    apiBase: string
    clientId: string
    clientSecret: string
    timeout: number
    accessToken?: string
    refreshToken?: string
    oauth2TokenGetter?: OAuth2TokenGetter
    oauth2TokenSetter?: OAuth2TokenSetter
    logger?: Logger
  }) {
    this.apiBase = params.apiBase
    this.clientId = params.clientId
    this.clientSecret = params.clientSecret
    this.timeout = params.timeout
    this._accessToken = params.accessToken
    this._refreshToken = params.refreshToken
    this.oauth2TokenGetter = params.oauth2TokenGetter
    this.oauth2TokenSetter = params.oauth2TokenSetter

    // this.client = new OAuth2.Client(this.clientId)
    // this.auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString(
    //   "base64"
    // )
    this.log = (params.logger ?? get_log)("apiv5.oauth2")
  }

  private getPath(): string {
    return `https://${this.apiBase}/oauth2/token`
  }

  private static getHeaders(): Record<string, string> {
    return {
      "cache-control": "no-cache",
      "content-type": "application/x-www-form-urlencoded",
    }
  }

  get accessToken(): string | undefined {
    if (this.oauth2TokenGetter) {
      return (
        this.oauth2TokenGetter("access_token", this.clientId) ||
        this._accessToken
      )
    }
    return this._accessToken
  }

  set accessToken(accessToken: string | undefined) {
    if (this.oauth2TokenSetter && accessToken) {
      this.oauth2TokenSetter("access_token", this.clientId, accessToken)
    }
    this._accessToken = accessToken
  }

  get refreshToken(): string | undefined {
    if (this.oauth2TokenGetter) {
      return (
        this.oauth2TokenGetter("refresh_token", this.clientId) ||
        this._refreshToken
      )
    }
    return this._refreshToken
  }

  set refreshToken(refreshToken: string | undefined) {
    if (this.oauth2TokenSetter && refreshToken) {
      this.oauth2TokenSetter("refresh_token", this.clientId, refreshToken)
    }
    this._refreshToken = refreshToken
  }

  get credentials(): Record<string, string> {
    return {
      client_id: this.clientId,
      client_secret: this.clientSecret,
      refresh_token: this.refreshToken as string,
    }
  }

  async getToken(): Promise<void> {
    this.log.info?.("OAUTH2 : Get Token")
    try {
      const params = new URLSearchParams({
        grant_type: "client_credentials",
        client_id: this.clientId,
        client_secret: this.clientSecret,
      })

      const response = await fetch(this.getPath(), {
        method: "POST",
        headers: OAuth2Api.getHeaders(),
        body: params.toString(),
        // timeout: this.timeout,
      })

      const result = await response.json()
      this.tokenSaver(result)
      this.log.info?.(`Token : ${this._accessToken}`)
    } catch (error) {
      this.handleRequestError(error)
    }
  }

  private tokenSaver(request: any): void {
    this.accessToken = request.access_token
    this.refreshToken = request.refresh_token
  }

  async refreshTokens(): Promise<void> {
    this.log.info?.("OAUTH2 : Refresh Token")
    try {
      if (this.refreshToken) {
        const params = new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: this.refreshToken,
          client_id: this.clientId,
          client_secret: this.clientSecret,
        })

        const response = await fetch(this.getPath(), {
          method: "POST",
          headers: OAuth2Api.getHeaders(),
          body: params.toString(),
          //   timeout: this.timeout, // TODO
        })

        const result = await response.json()
        this.tokenSaver(result)
        this.log.info?.(`OAUTH2 : Refresh Token : ${this._accessToken}`)
      } else {
        this.accessToken = undefined
        this.refreshToken = undefined
        this.log.warn?.("OAUTH2 : the Refresh Token is empty, reset tokens.")
      }
    } catch (error) {
      this.handleRequestError(error)
    } finally {
      if (!this.accessToken) {
        this.log.info?.(
          "OAUTH2 : Access Token for Refresh Token not exist, requests a new Access Token"
        )
        await this.getToken()
      }
    }
  }

  private handleRequestError(error: any): void {
    if (error.type === "request-timeout") {
      throw new ApiV5Timeout(`${this.getPath()} timeout : ${this.timeout} sec`)
    }
    if (error.message.includes("network request failed")) {
      throw new ApiV5ConnectionError(
        `Failed to establish a new connection: Name or service not known : ${this.getPath()}`
      )
    }
    // if (error instanceof OAuth2.UnauthorizedClientError) {
    //   throw new ApiV5AuthenticationError(
    //     `Authentication Error : ${error.message}`
    //   )
    // }
    // if (error instanceof OAuth2.AccessDeniedError) {
    //   this.accessToken = undefined
    //   this.refreshToken = undefined
    //   this.log.warning(
    //     "OAUTH2 : (access_denied) invalid token values, reset tokens"
    //   )
    // } else {
    throw new Apiv5ExceptionError(`Error : ${error.message}`)
    // }
  }
}

// Error classes implementation
class ApiV5NoConfig extends Error {}
class ApiV5NotFound extends Error {
  constructor(response: Response) {
    super("Not Found")
  }
}
class ApiV5Unauthorized extends Error {
  constructor(response: Response) {
    super("Unauthorized")
  }
}
class ApiV5Forbidden extends Error {
  constructor(response: Response) {
    super("Forbidden")
  }
}
class ApiV5Conflict extends Error {
  constructor(response: Response) {
    super("Conflict")
  }
}
class ApiV5RateLimited extends Error {
  constructor(response: Response) {
    super("Rate Limited")
  }
}
class ApiV5BadRequest extends Error {
  constructor(response: Response) {
    super("Bad Request")
  }
}
class ApiV5ServerError extends Error {
  constructor(response: Response) {
    super("Server Error")
  }
}
class ApiV5Timeout extends Error {
  constructor(message: string) {
    super(message)
  }
}
class ApiV5ConnectionError extends Error {
  constructor(message: string) {
    super(message)
  }
}
class ApiV5AuthenticationError extends Error {
  constructor(message: string) {
    super(message)
  }
}
class Apiv5ExceptionError extends Error {
  constructor(message: string) {
    super(message)
  }
}

type Logger = (name: string) => {
  debug?: (message: string) => void
  info?: (message: string) => void
  warn?: (message: string) => void
  error?: (message: string) => void
}

// Helper functions
function get_log(name: string): any {
  // Implement your logging functionality here
  return console
}

interface OAuth2TokenGetter {
  (type: "access_token" | "refresh_token", clientId: string): string | undefined
}

interface OAuth2TokenSetter {
  (
    type: "access_token" | "refresh_token",
    clientId: string,
    token: string
  ): void
}

export class ApiV5Client {
  private apiBase: string
  private clientId: string
  private clientSecret: string
  private timeout: number | undefined
  private accessToken: string | undefined
  private refreshToken: string | undefined
  private oauth2TokenGetter: OAuth2TokenGetter | undefined
  private oauth2TokenSetter: OAuth2TokenSetter | undefined
  private log: ReturnType<Logger>
  private oauth: OAuth2Api
  private auth: any

  constructor({
    apiBase,
    clientId,
    clientSecret,
    timeout,
    accessToken,
    refreshToken,
    oauth2TokenGetter,
    oauth2TokenSetter,
    logger,
  }: {
    apiBase: string
    clientId: string
    clientSecret: string
    timeout?: number
    accessToken?: string
    refreshToken?: string
    oauth2TokenGetter?: OAuth2TokenGetter
    oauth2TokenSetter?: OAuth2TokenSetter
    logger?: Logger
  }) {
    this.apiBase = apiBase
    this.clientId = clientId
    this.clientSecret = clientSecret
    this.timeout = timeout
    this.accessToken = accessToken
    this.refreshToken = refreshToken
    this.oauth2TokenGetter = oauth2TokenGetter
    this.oauth2TokenSetter = oauth2TokenSetter

    this.log = (logger ?? get_log)("apiv5.apiv5client")

    if (!this.clientId || !this.clientSecret) {
      throw new ApiV5NoConfig("Missing client_id or client_secret.")
    }
    if (!this.apiBase) {
      throw new ApiV5NoConfig("Missing Api Base.")
    }

    if (
      (oauth2TokenGetter === undefined) !==
      (oauth2TokenSetter === undefined)
    ) {
      throw new ApiV5NoConfig(
        "You must either specify both the oauth2 token setter and getter, or neither."
      )
    }

    this.oauth = new OAuth2Api({
      apiBase: this.apiBase,
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      timeout: this.timeout!,
      accessToken: this.accessToken,
      refreshToken: this.refreshToken,
      oauth2TokenGetter: this.oauth2TokenGetter,
      oauth2TokenSetter: this.oauth2TokenSetter,
      logger: logger,
    })

    if (!this.oauth.accessToken) {
      this.oauth.getToken()
    }
  }

  setAccessToken(accessToken: string) {
    this.accessToken = accessToken
    this.oauth.accessToken = accessToken
  }

  setRefreshToken(refreshToken: string) {
    this.refreshToken = refreshToken
    this.oauth.refreshToken = refreshToken
  }

  static header(): Record<string, string> {
    return { "Content-Type": "application/json" }
  }

  private prepareRequest(
    subPath: string,
    headers?: Record<string, string>,
    data?: Record<string, any>,
    json?: Record<string, any>,
    params?: Record<string, any>,
    includeAuth: boolean = true
  ): [string, RequestInit] {
    const url = `https://${this.apiBase}${subPath}`
    this.log.debug?.(`Prepare Request : ${url}`)
    const allHeaders = { ...ApiV5Client.header(), ...headers }
    const authHeaders = includeAuth
      ? { Authorization: `Bearer ${this.oauth.accessToken}` }
      : {}
    const requestInit: RequestInit = {
      headers: { ...allHeaders, ...authHeaders } as HeadersInit,
      body: JSON.stringify(json || data),
    }

    return [url, requestInit]
  }

  private async executeRequest(
    url: string,
    method: string,
    options: RequestInit
  ): Promise<Response> {
    this.log.debug?.(`Execute Request : ${method} : ${url}`)
    options.method = method

    try {
      const response = await fetch(url, options)

      if (response.status === 404 || response.status === 410) {
        throw new ApiV5NotFound(response)
      } else if (response.status === 401) {
        throw new ApiV5Unauthorized(response)
      } else if (response.status === 403) {
        throw new ApiV5Forbidden(response)
      } else if (response.status === 409) {
        throw new ApiV5Conflict(response)
      } else if (response.status === 429) {
        throw new ApiV5RateLimited(response)
      } else if (response.status >= 400 && response.status < 500) {
        throw new ApiV5BadRequest(response)
      } else if (response.status >= 500) {
        throw new ApiV5ServerError(response)
      }

      return response
    } catch (error: any) {
      if (error.type === "request-timeout") {
        throw new ApiV5Timeout(`${url} timeout : ${this.timeout} sec`)
      }
      if (error.message.includes("network request failed")) {
        throw new ApiV5ConnectionError(
          `Failed to establish a new connection: Name or service not known : ${url}`
        )
      }
      throw error
    }
  }

  async call(
    subPath: string,
    params?: Record<string, any>,
    method: string = "GET",
    data?: Record<string, any>,
    json?: Record<string, any>,
    headers?: Record<string, string>,
    includeAuth: boolean = true
  ): Promise<Response> {
    this.log.debug?.(`Call : ${method} : ${subPath}`)
    const [url, requestInit] = this.prepareRequest(
      subPath,
      headers,
      data,
      json,
      params,
      includeAuth
    )

    try {
      const result = await this.executeRequest(url, method, requestInit)
      return result
    } catch (error) {
      if (error instanceof ApiV5Unauthorized) {
        this.log.warn?.("401 Unauthorized response to API request.")
        if (this.oauth.accessToken) {
          this.log.info?.("Refreshing access token")
          await this.oauth.refreshTokens()
        } else {
          this.log.info?.("Get access token")
          await this.oauth.getToken()
        }
        return this.call(
          subPath,
          params,
          method,
          data,
          json,
          headers,
          includeAuth
        )
      }
      throw error
    }
  }
}
