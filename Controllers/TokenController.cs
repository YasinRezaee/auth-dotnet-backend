using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using YtMovieApis.Models.Domain;
using YtMovieApis.Models.DTO;
using YtMovieApis.Repositories.Abstract;

namespace YtMovieApis.Controllers
{
    [Route("api/Token")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly DatabaseContext _ctx;
        private readonly ITokenService _service;

        public TokenController(DatabaseContext ctx, ITokenService service)
        {
            _ctx = ctx;
            _service = service;
        }

        // --- Refresh Token ---
        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] RefreshTokenRequest tokenApiModel)
        {
            if (tokenApiModel is null)
                return BadRequest("Invalid client request");

            string accessToken = tokenApiModel.AccessToken;
            string refreshToken = tokenApiModel.RefreshToken;

            var principal = _service.GetPrincipalFromExpiredToken(accessToken);
            var username = principal.Identity?.Name;

            if (username == null)
                return BadRequest("Invalid token");

            var user = _ctx.TokenInfo.SingleOrDefault(u => u.Usename == username);

            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiry <= DateTime.Now)
                return BadRequest("Invalid client request");

            var newAccessToken = _service.GetToken(principal.Claims);
            var newRefreshToken = _service.GetRefreshToken();

            user.RefreshToken = newRefreshToken;
            _ctx.SaveChanges();

            return Ok(new RefreshTokenRequest
            {
                AccessToken = newAccessToken.TokenString,
                RefreshToken = newRefreshToken
            });
        }

        // --- Revoke Token ---
        [HttpPost("revoke")]
        [Authorize]
        public IActionResult Revoke()
        {
            var username = User.Identity?.Name;

            if (username == null)
                return BadRequest("Invalid user");

            var user = _ctx.TokenInfo.SingleOrDefault(u => u.Usename == username);

            if (user == null)
                return BadRequest("No token found for user");

            user.RefreshToken = null;
            _ctx.SaveChanges();

            return Ok(true);
        }
    }
}
