using JWTDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTDemo.Controllers
{

    [ApiController]
    public class DemoController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public DemoController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [Route("GetTestUnAuthorise")]
        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> GetTestUnAuthorise()
        {
            return Ok("Hello world from GetTestUnAuthorise");
        }


        [Route("GetTestAuthorise")]
        [Authorize]
        [HttpPost]
        public async Task<IActionResult> GetTestAuthorise()
        {
            return Ok("Hello world from GetTestAuthorise");
        }

        //[Route("CheckLogin")]
        //[AllowAnonymous]
        //[HttpPost]
        //public async Task<IActionResult> CheckLogin(UserModel usr)
        //{
        //   if(usr.LoginID == "admin" && usr.Password == "password")
        //    {
        //        var claims = new[] {
        //                new Claim(JwtRegisteredClaimNames.Sub, _configuration["Jwt:Subject"]),
        //                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        //                new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
        //                new Claim("UserId", usr.LoginID)
        //            };
        //        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        //        var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        //        var token = new JwtSecurityToken(
        //            _configuration["Jwt:Issuer"],
        //            _configuration["Jwt:Audience"],
        //        claims,
        //        expires: DateTime.UtcNow.AddMinutes(10),
        //            signingCredentials: signIn);
        //        usr.UserMessage = "Login Success";
        //        usr.UserToken = new JwtSecurityTokenHandler().WriteToken(token);
        //    }
        //    else
        //    {
        //        usr.UserMessage = "Login Failed";
        //    }
        //    return Ok(usr);
        //}

        [Route("CheckLogin")]
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> CheckLogin(UserModel usr)
        {
            if (usr.LoginID == "admin" && usr.Password == "password")
            {
                var claims = new[]
                {
            new Claim(JwtRegisteredClaimNames.Sub, _configuration["Jwt:Subject"]),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
            new Claim("UserId", usr.LoginID)
        };
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var token = new JwtSecurityToken(
                    _configuration["Jwt:Issuer"],
                    _configuration["Jwt:Audience"],
                    claims,
                    expires: DateTime.UtcNow.AddMinutes(1),
                    signingCredentials: signIn);

                usr.UserMessage = "Login Success";
                usr.UserToken = new JwtSecurityTokenHandler().WriteToken(token);

                // Generate and attach refresh token
                var refreshToken = GenerateRefreshToken();
                usr.RefreshToken = refreshToken;

             

                
            }
            else
            {
                usr.UserMessage = "Login Failed";
               
            }
            // Store the refresh token securely on the client side
            return Ok(usr);
        }
        [Route("GenerateRefreshToken")] // Add this attribute route
        [HttpGet]
        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

    }
}
