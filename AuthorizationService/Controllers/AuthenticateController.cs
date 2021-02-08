using AuthorizationService.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthorizationService.Repository;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;

namespace AuthorizationService.Controllers
{   
    [AllowAnonymous]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private  IAuthenticationRepository authenticationRepository;
        private IConfiguration configuration;
        private readonly log4net.ILog _log4net;

        public AuthenticateController(IAuthenticationRepository authenticationRepository,IConfiguration configuration)
        {
            this.authenticationRepository = authenticationRepository;
            this.configuration = configuration;
            _log4net = log4net.LogManager.GetLogger(typeof(AuthenticateController));
        }


        //Action Method to Generate JWT 
        [HttpGet]
        public IActionResult TokenGeneration(string name,string password )
        {
            _log4net.Info("Trying to Login");
            User user =new User { Name = name, Password = password };
            
            //check if user exist using the method Authentication() in JwtAuthenticationRepository
            bool isUserExist = authenticationRepository.Authentication(user.Name,user.Password);


            if (!isUserExist)
            {
                _log4net.Warn("Unauthorised Access !!!  Check user credentials");
                return new UnauthorizedResult();
            }

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwtoken:SecretKey"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);


            var claims = new List<Claim>
            {
                new Claim("UserId", user.UserId.ToString())
            };


            var token = new JwtSecurityToken(
                        issuer: configuration["Jwtoken:Issuer"],
                        audience: configuration["Jwtoken:Audience"],
                        claims: claims,
                        expires: DateTime.Now.AddSeconds(30),
                        signingCredentials: credentials);

            return new OkObjectResult(new JwtSecurityTokenHandler().WriteToken(token));
        }

       
    }
}
