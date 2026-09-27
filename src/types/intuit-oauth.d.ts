declare module "intuit-oauth" {
  interface OAuthClientConfig {
    clientId: string;
    clientSecret: string;
    environment: string;
    redirectUri: string;
    logging?: boolean;
  }

  interface AuthorizeUriOptions {
    scope: string[];
    state?: string;
  }

  interface TokenResponse {
    token: {
      access_token: string;
      refresh_token: string;
      realmId: string;
      createdAt: number;
      x_refresh_token_expires_in?: number;
    };
  }

  class OAuthClient {
    constructor(config: OAuthClientConfig);
    authorizeUri(options: AuthorizeUriOptions): string;
    createToken(url: string): Promise<TokenResponse>;
    refresh(): Promise<TokenResponse>;
    setToken(token: Record<string, unknown>): void;
    static scopes: {
      Accounting: string;
      OpenId: string;
      Payment: string;
      Payroll: string;
      TimeTracking: string;
      Benefits: string;
      Profile: string;
      Email: string;
      Phone: string;
      Address: string;
      Intuit_name: string;
      ProjectManagement: string;
      CustomFields: string;
      Dimensions: string;
      SalesTax: string;
    };
  }

  export default OAuthClient;
}
