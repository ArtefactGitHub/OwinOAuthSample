using Constants;
using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(AuthorizationServer.Startup))]

namespace AuthorizationServer
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // Setup Authorization Server
            var option = new OAuthAuthorizationServerOptions {
                // アクセストークンエンドポイントの設定
                TokenEndpointPath = new PathString("/OAuth/Token"),

                // HTTPを許可する（リリース時はHTTPSにしないといけないですが、デバックのときはこうしておきましょう）
                AllowInsecureHttp = true,

                // イベントコールバックメソッドの設定
                Provider = new OAuthAuthorizationServerProvider {
                    OnValidateTokenRequest = ValidateTokenRequest,
                    OnValidateAuthorizeRequest = ValidateAuthorizeRequest,
                    // ClientIdとClientSecretの検証
                    OnValidateClientAuthentication = ValidateClientAuthentication,
                    // ResourceOwnerCredentialsのときの処理
                    OnGrantResourceOwnerCredentials = GrantResourceOwnerCredentials,
                    OnTokenEndpoint = TokenEndpoint,
                    OnTokenEndpointResponse = TokenEndpointResponse,
                    OnAuthorizationEndpointResponse = AuthorizationEndpointResponse,

                },

                // リフレッシュトークンの生成と受信コールバックの設定
                RefreshTokenProvider = new AuthenticationTokenProvider {
                    OnCreate = CreateRefreshToken,
                    OnReceive = ReceiveRefreshToken,
                },

                // AccessTokenExpireTimeSpanを10分に設定する(省略した場合のデフォルトは20分)
                AccessTokenExpireTimeSpan = new TimeSpan(0, 10, 0)
            };

            app.UseOAuthAuthorizationServer(option);
        }

        /// <summary>
        /// 要求の発信元が登録された「client_id」であること、およびそのクライアントの正しい資格情報が
        /// 要求に存在することを検証するために呼び出されます。Webアプリケーションが基本認証資格情報を受け入れる場合、
        /// context.TryGetBasicCredentials（out clientId、out clientSecret）が呼び出されて、
        /// リクエストヘッダーに存在する場合にこれらの値を取得します。
        /// Webアプリケーションが「client_id」と「client_secret」をフォームエンコードされたPOSTパラメータとして受け入れる場合、
        /// context.TryGetFormCredentials（out clientId、out clientSecret）を呼び出して、
        /// リクエストの本文にこれらの値がある場合にそれらの値を取得できます。
        /// context.Validatedが呼び出されない場合、リクエストはこれ以上続行されません。
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId;
            string clientSecret;

            // ClientIDとClientSecretをヘッダまたはフォームからGetする
            if (context.TryGetBasicCredentials(out clientId, out clientSecret) ||
                context.TryGetFormCredentials(out clientId, out clientSecret))
            {
                // clientId と clientSecret をチェックして接続を許可する場合は
                // context.Validated();する
                context.Validated();

            }
            return Task.FromResult(0);
        }

        /// <summary>
        /// 承認エンドポイントへのリクエストごとに呼び出され、リクエストが有効で続行する必要があるかどうかを判断します。
        /// OAuthAuthorizationServerProviderを使用するときのデフォルトの動作は、
        /// 検証されたクライアントリダイレクトURIを使用して、整形式の要求が処理を続行することを前提としています。
        /// アプリケーションは追加の制約を追加できます。
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task ValidateAuthorizeRequest(OAuthValidateAuthorizeRequestContext context)
        {
            context.Validated();
            return Task.FromResult(0);
        }

        /// <summary>
        /// トークンエンドポイントへのリクエストごとに呼び出され、リクエストが有効で続行する必要があるかどうかを判断します。
        /// OAuthAuthorizationServerProviderを使用する場合のデフォルトの動作は、
        /// 検証済みのクライアント資格情報を使用して、整形式の要求が処理を続行することを前提としています。アプリケーションは追加の制約を追加できます。
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task ValidateTokenRequest(OAuthValidateTokenRequestContext context)
        {
            //TODO: Determine which grant types will actually support - these will probably be the only ones
            if (!context.TokenRequest.IsAuthorizationCodeGrantType &&
                !context.TokenRequest.IsResourceOwnerPasswordCredentialsGrantType &&
                !context.TokenRequest.IsRefreshTokenGrantType)
            {
                context.Rejected();
                context.SetError("invalid_grant_type", "Only grant_type=authorization_code, grant_type=password or grant_type=refresh_token are accepted by this server.");
                return Task.FromResult(0);
            }

            return Task.FromResult(context.Validated());
        }

        private Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            if (context.UserName == null || context.Password == null)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return Task.FromResult(0);
            }

            // usernameとpasswordをGetする
            string username = context.UserName;
            string password = context.Password;
            var scopes = GetScopes(context.Scope);

            // username と password をチェックして接続を許可する場合は identity を作成して context.Validated(identity) する
            var identity = new ClaimsIdentity(new GenericIdentity(username, OAuthDefaults.AuthenticationType), scopes.Select(x => new Claim("urn:oauth:scope", x)));

            // ここでセットしたidentityがTokenになる
            context.Validated(identity);

            return Task.FromResult(0);
        }

        /// <summary>
        /// スコープの取得
        /// スコープの指定が無い場合はデフォルトのスコープをセットする
        /// 指定がある場合はその値で上書きする
        /// </summary>
        /// <param name="scopes"></param>
        /// <returns></returns>
        private IEnumerable<string> GetScopes(IList<string> scopes)
        {
            var result = (scopes.All(x => string.IsNullOrWhiteSpace(x)) ?
                            new List<string>() { ScopeTypes.Standard }
                          : scopes.Where(x => !string.IsNullOrWhiteSpace(x)).ToList());
            return result.Distinct().AsEnumerable();
        }

        /// <summary>
        /// 成功したトークンエンドポイントリクエストの最終段階で呼び出されます。
        /// アプリケーションは、アクセスまたはリフレッシュトークンの発行に使用されているクレームの最終的な変更を行うために、
        /// この呼び出しを実装できます。この呼び出しは、トークンエンドポイントのJSON応答本文に追加の応答パラメーターを追加するためにも使用できます。
        /// </summary>
        /// <param name="context"></param>
        private Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            return Task.FromResult(0);
        }

        #region RefreshToken

        private void CreateRefreshToken(AuthenticationTokenCreateContext context)
        {
            // リフレッシュトークンの有効期限を設定する(1日)
            int expire = 24 * 60 * 60;
            context.Ticket.Properties.ExpiresUtc = new DateTimeOffset(DateTime.Now.AddSeconds(expire));

            context.SetToken(context.SerializeTicket());
        }

        private void ReceiveRefreshToken(AuthenticationTokenReceiveContext context)
        {
            // このおまじないをするとCreateRefreshToken()イベントが発生してアクセストークンとリフレッシュトークンが再生成される
            context.DeserializeTicket(context.Token);
        }

        #endregion

        /// <summary>
        /// AuthorizationEndpointが応答を呼び出し元にリダイレクトする前に呼び出されます。
        /// 応答は、暗黙的なフローを使用する場合はトークン、認証コードフローを使用する場合はAuthorizationEndpointになります。
        /// アプリケーションは、アクセスまたはリフレッシュトークンの発行に使用されているクレームの最終的な変更を行うために、
        /// この呼び出しを実装できます。この呼び出しは、承認エンドポイントの応答に追加の応答パラメーターを追加するためにも使用できます。
        /// </summary>
        /// <param name="context"></param>
        private Task AuthorizationEndpointResponse(OAuthAuthorizationEndpointResponseContext context)
        {
            return Task.FromResult(0);
        }

        /// <summary>
        /// トークンエンドポイントでコードを利用した後に受信したトークンを含むOpenIdConnectMessageを取得または設定します。
        /// 
        /// RefreshToken処理の後に実行される？
        /// </summary>
        /// <param name="context"></param>
        private Task TokenEndpointResponse(OAuthTokenEndpointResponseContext context)
        {
            return Task.FromResult(0);
        }
    }
}
