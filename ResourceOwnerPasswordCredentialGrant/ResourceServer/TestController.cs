using Constants;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace ResourceServer
{
    public class MyAuthorizeFilter : AuthorizeAttribute
    {
        public string Scopes { get; } = ScopeTypes.Standard;

        public MyAuthorizeFilter() { }

        public MyAuthorizeFilter(params string[] scopes) => Scopes = string.Join(" ", scopes);

        public override void OnAuthorization(HttpActionContext actionContext)
        {
            base.OnAuthorization(actionContext);
        }

        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            var currentIdentity = actionContext.RequestContext.Principal.Identity;
            if (!currentIdentity.IsAuthenticated)
                return false;

            // 下記2つのどちらかに当てはまる場合は承認しない
            // 　・API属性のスコープが空ではない、かつトークンのスコープが全て空
            // 　・トークンのスコープに、API属性のスコープが1つも存在しない
            var scopeClaims = (actionContext.RequestContext.Principal as ClaimsPrincipal).FindAll("urn:oauth:scope");
            var attribute = actionContext.ActionDescriptor.GetCustomAttributes<MyAuthorizeFilter>().Single();
            if((!string.IsNullOrWhiteSpace(attribute.Scopes) && scopeClaims.All(scopeClaim => string.IsNullOrWhiteSpace(scopeClaim.Value)))
            || (!scopeClaims.Any(scopeClaim => attribute.Scopes.Contains(scopeClaim.Value))))
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
            }

            return true;
        }
    }

    // クラスの追加→WebAPIコントローラクラス
    // http://localhost:38385/api/Test
    // で実行されるWebAPI
    // [Authorize]属性がついているので、AccessTokenが有効な場合だけ実行される
    // AccessTokenの検証はOwinが勝手にやってくれる
    public class TestController : ApiController
    {
        [HttpGet]
        [MyAuthorizeFilter]
        public IEnumerable<string> Get()
        {
            // this.User.Identity が Token をデコードしたもの
            string value = $"Your Name is {this.User.Identity.Name}";
            return new string[] { "result value", value };
        }

        [HttpPost]
        [MyAuthorizeFilter(ScopeTypes.Standard, ScopeTypes.UploadOnly)]
        public IEnumerable<string> Post(JObject hoge)
        {
            // this.User.Identity が Token をデコードしたもの
            string value = $"Your Name is {this.User.Identity.Name}";
            
            foreach(var pair in hoge)
            {
                Debug.WriteLine($"key : {pair.Key}");
                Debug.WriteLine($"value : {pair.Value}");
            }
            return new string[] { $"Authorize Scope! post data is {hoge}" };
        }
    }
}
