using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace ResourceServer
{
    public class RollType
    {
        public const string User = "User";
        public const string Admin = "Admin";
        public const string Uploader = "Uploader";
    }

    public class MyAuthorizeFilter : AuthorizeAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            base.OnAuthorization(actionContext);
        }

        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            var currentIdentity = actionContext.RequestContext.Principal.Identity;
            if (!currentIdentity.IsAuthenticated)
                return false;

            // アップロードRoll判定
            var actionCustomAttribute = actionContext.ActionDescriptor.GetCustomAttributes<MyAuthorizeFilter>().Single();
            if (actionCustomAttribute.Roles.Contains(RollType.Uploader))
            {
                var scopes = ((System.Security.Claims.ClaimsPrincipal)actionContext.RequestContext.Principal).FindAll("urn:oauth:scope");
                //if (!actionContext.RequestContext.Principal.IsInRole(RollType.Uploader))
                if (scopes.Count() == 0 || !scopes.Any(x => x.Value == RollType.Uploader))
                {
                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                }
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
        [Authorize]
        public IEnumerable<string> Get()
        {
            // this.User.Identity が Token をデコードしたもの
            string value = $"Your Name is {this.User.Identity.Name}";
            return new string[] { "result value1", value };
        }

        [HttpGet]
        [MyAuthorizeFilter(Roles = "Uploader")]
        [Route("api/TestUploader")]
        public IEnumerable<string> TestUploader()
        {
            // this.User.Identity が Token をデコードしたもの
            string value = $"Your Name is {this.User.Identity.Name}";
            return new string[] { "Authorize Roll Uploader!" };
        }
    }
}