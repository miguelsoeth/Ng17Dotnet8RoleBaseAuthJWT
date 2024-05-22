using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using API.Dtos;
using API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;


namespace API.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController:ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;


        public AccountController(UserManager<AppUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IConfiguration configuration
        )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;

        }

        // api/account/register

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult<string>> Register(RegisterDto registerDto)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new AppUser{
                Email = registerDto.Email,
                FullName = registerDto.FullName,
                Document = registerDto.Document,
                UserName = registerDto.Email
            };

            var result = await _userManager.CreateAsync(user,registerDto.Password);

            if(!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            
            if(registerDto.Roles is null){
                    await _userManager.AddToRoleAsync(user,"User");
            }else{
                foreach(var role in registerDto.Roles)
                {
                    await _userManager.AddToRoleAsync(user,role);
                }
            }
    

        return Ok(new AuthResponseDto{
            IsSuccess = true,
            Message = "Account Created Sucessfully!"
        });

        }

        //api/account/login
        [AllowAnonymous]
        [HttpPost("login")]

        public async Task<ActionResult<AuthResponseDto>> Login(LoginDto loginDto)
        {
            if(!ModelState.IsValid)
            {
               return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(loginDto.Email);

            if(user is null)
            {
                return Unauthorized(new AuthResponseDto{
                    IsSuccess = false,
                    Message = "User not found with this email",
                });
            }

            var result = await _userManager.CheckPasswordAsync(user,loginDto.Password);

            if(!result){
                return Unauthorized(new AuthResponseDto{
                    IsSuccess=false,
                    Message= "Senha inválida."
                });
            }

            bool isLocked = await _userManager.IsLockedOutAsync(user);
            if (isLocked)
            {
                return Unauthorized(new AuthResponseDto{
                    IsSuccess=false,
                    Message= "Usuário bloqueado."
                });
            }

            
            var token = GenerateToken(user);
            var refreshToken = GenerateRefreshToken();
            int.TryParse(_configuration.GetSection("JWTSetting").GetSection("RefreshTokenValidityInDays").Value!, out int RefreshTokenValidityInDays);
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(RefreshTokenValidityInDays);
            await _userManager.UpdateAsync(user);
            
            return Ok(new AuthResponseDto{
                Token = token,
                IsSuccess = true,
                Message = "Login Success.",
                RefreshToken = refreshToken
            });


        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private string GenerateToken(AppUser user){
            var tokenHandler = new JwtSecurityTokenHandler();
            
            var key = Encoding.ASCII
            .GetBytes(_configuration.GetSection("JWTSetting").GetSection("securityKey").Value!);

            var roles = _userManager.GetRolesAsync(user).Result;

            List<Claim> claims = 
            [
                new (JwtRegisteredClaimNames.Email,user.Email??""),
                new (JwtRegisteredClaimNames.Name,user.FullName??""),
                new (JwtRegisteredClaimNames.NameId,user.Id ??""),
                new (JwtRegisteredClaimNames.Aud,
                _configuration.GetSection("JWTSetting").GetSection("validAudience").Value!),
                new (JwtRegisteredClaimNames.Iss,_configuration.GetSection("JWTSetting").GetSection("validIssuer").Value!)
            ];


            foreach(var role in roles)

            {
                claims.Add(new Claim(ClaimTypes.Role,role));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256
                )
            };


            var token  = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
           

        }

        //api/account/login
        [AllowAnonymous]
        [HttpPost("refresh-token")]

        public async Task<ActionResult<AuthResponseDto>> RefreshToken(TokenDto tokenDto)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var principal = GetPrincipalFromExpiredToken(tokenDto.Token);
            var user = await _userManager.FindByEmailAsync(tokenDto.Email);
            if (principal is null 
                || user is null 
                || user.RefreshToken != tokenDto.RefreshToken 
                || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return BadRequest(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Pedido do cliente inválido!"
                });
            }

            var newJwtToken = GenerateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            int.TryParse(_configuration.GetSection("JWTSetting").GetSection("RefreshTokenValidityInDays").Value!, out int RefreshTokenValidityInDays);
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(RefreshTokenValidityInDays);

            await _userManager.UpdateAsync(user);

            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Token = newJwtToken,
                RefreshToken = newRefreshToken,
                Message = "Token revalidado com sucesso!"
            });
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey =
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("JWTSetting")
                        .GetSection("securityKey").Value!)),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                    StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Token inválido!");
            }

            return principal;
        }

        //api/account/detail
        [HttpGet("detail")]
        public async Task<ActionResult<UserDetailDto>> GetUserDetail()
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(currentUserId!);


            if(user is null)
            {
                return NotFound(new AuthResponseDto{
                    IsSuccess = false,
                    Message = "User not found"
                });
            }

            return Ok(new UserDetailDto{
                Id = user.Id,
                Email = user.Email,
                FullName = user.FullName,
                Document = user.Document,
                Roles = [..await _userManager.GetRolesAsync(user)],
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                AccessFailedCount = user.AccessFailedCount,
                LockedOut = user.LockoutEnd > DateTimeOffset.Now
            });

        }
        
        //api/account/detail/{id}
        [HttpGet("detail/{id}")]
        public async Task<ActionResult<UserDetailDto>> GetDetailById([FromRoute] string id)
        {
            var user = await _userManager.FindByIdAsync(id);

            if(user is null)
            {
                return NotFound(new AuthResponseDto{
                    IsSuccess = false,
                    Message = "User not found"
                });
            }

            return Ok(new UserDetailDto{
                Id = user.Id,
                Email = user.Email,
                FullName = user.FullName,
                Document = user.Document,
                Roles = [..await _userManager.GetRolesAsync(user)],
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                AccessFailedCount = user.AccessFailedCount,
                LockedOut = user.LockoutEnd > DateTimeOffset.Now
            });
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserDetailDto>>> GetUsers()
        {
            var users = await _userManager.Users.Select(u=> new UserDetailDto{
                Id = u.Id,
                Email=u.Email,
                FullName=u.FullName,
                Document = u.Document,
                Roles=_userManager.GetRolesAsync(u).Result.ToArray()
            }).ToListAsync();

            return Ok(users);
        }
        
        [HttpPut("edit/{id}")]
        public async Task<ActionResult<string>> EditUser([FromRoute]string id, [FromBody]EditDto editDto)
        {
            // Check if the provided user ID is valid
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound("User not found");
            }
            
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Update user information based on UserDetailDto
            if (!editDto.FullName.IsNullOrEmpty()) user.FullName = editDto.FullName;
            if (!editDto.Document.IsNullOrEmpty()) user.Document = editDto.Document;
            if (!editDto.Email.IsNullOrEmpty()) user.Email = editDto.Email;
            
            // Change password
            if (!editDto.Password.IsNullOrEmpty())
            {
                var pwdToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                var pwdResult = await _userManager.ResetPasswordAsync(user, pwdToken, editDto.Password!);
                if(!pwdResult.Succeeded)
                {
                    return BadRequest(pwdResult.Errors);
                }
            }
            
            // Update roles if provided
            if (editDto.Roles != null && editDto.Roles.Any())
            {
                // Get user roles
                var userRoles = await _userManager.GetRolesAsync(user);
                
                // Remove roles that are not in the edited roles
                var rolesToRemove = userRoles.Where(role => !editDto.Roles.Contains(role)).ToList();
                if (rolesToRemove.Any())
                {
                    await _userManager.RemoveFromRolesAsync(user, rolesToRemove);
                }

                // Add roles that are in the edited roles but not currently assigned to the user
                var rolesToAdd = editDto.Roles!.Where(role => !userRoles.Contains(role)).ToList();
                if (rolesToAdd.Any())
                {
                    await _userManager.AddToRolesAsync(user, rolesToAdd);
                }
            }

            if (editDto.Disabled != null)
            {
                await _userManager.SetLockoutEnabledAsync(user, true);
                if (editDto.Disabled.Value)
                {
                    await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue); // Disable the user
                }
                else
                {
                    await _userManager.SetLockoutEndDateAsync(user, null); // Re-enable the user
                }
            }

            // Update the user
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Message = "User information updated successfully!"
            });
        }


    }
}