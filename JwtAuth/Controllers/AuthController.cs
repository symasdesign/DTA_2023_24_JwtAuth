using JwtAuth.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuth.Controllers {
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase {
        public static User user = new User(); // in prod. in DB speichern

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request) {
            CreatePasswordHash(request.Password, out byte[] passwordhash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash= passwordhash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        private static void CreatePasswordHash(string plainPassword, out byte[] passwordHash, out byte[] passwordSalt) {
            using (var hmac = new HMACSHA256()) {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(plainPassword));
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request) {
            if(user.Username != request.Username) {
                return BadRequest("User not found");
            }

            if(!VerifyPassword(request.Password, user.PasswordHash, user.PasswordSalt)) {
                return BadRequest("Wrong password");
            }
            var token = CreateToken(user);
            return Ok(token);
        }

        private string CreateToken(User user) {
            var claims = new List<Claim> {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role ,"Admin")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("my secure and very very very very long Key"));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
             );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private bool VerifyPassword(string password, byte[] passwordHash, byte[] passwordSalt) {
            using(var hmac = new HMACSHA256(passwordSalt)) {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }

            //var hmac = new HMACSHA256(passwordSalt);
            //try {
            //    var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            //    return computedHash.SequenceEqual(passwordHash);
            //} finally {
            //    hmac.Dispose();
            //}
        }
    }
}
