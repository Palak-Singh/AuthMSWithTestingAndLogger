using AuthorizationService.Controllers;
using AuthorizationService.Models;
using AuthorizationService.Repository;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Moq;
using NUnit.Framework;
using System.Collections.Generic;

namespace AuthorizationService.Testing
{
    [TestFixture]
    public class AuthenticationTests
    {
        private AuthenticateController _authenticateController;
        private Mock<IConfiguration> _configurationMock = new Mock<IConfiguration>();
        private Mock<IAuthenticationRepository> _authenticateRepositoryMock = new Mock<IAuthenticationRepository>();

        [SetUp]
        public void SetUp()
        {
            _authenticateController = new AuthenticateController(_authenticateRepositoryMock.Object, _configurationMock.Object);
        }

        [Test]
        [TestCase("Harry", "123pass")]
        [TestCase("Roy", "pass123")]
        public void TestTokenGeneration_WithValidCredentals_ReturnsOK(string userName, string password)
        {
            // Arrange
            _configurationMock.Setup(p => p["Jwtoken:SecretKey"]).Returns("This is an important key for authorization");
            _authenticateRepositoryMock.Setup(p => p.Authentication(userName,password)).Returns(true);
            
            // Act
            var data = _authenticateController.TokenGeneration(userName,password) as OkObjectResult;

            // Assert
            Assert.AreEqual(200, data.StatusCode);
        }

        [Test]
        public void TestTokenGeneration_WithInvalidCredentials_ReturnsUnauthorized()
        {
            // Arrange
            User user = new User { Name = "jh", Password = "j"};
            _configurationMock.Setup(p => p["Jwtoken:SecretKey"]).Returns("This is an important key for authorization");
            _authenticateRepositoryMock.Setup(p => p.Authentication("Roy", "pass123")).Returns(true);

            // Act
            var data = _authenticateController.TokenGeneration(user.Name, user.Password) as UnauthorizedResult;

            // Assert
            Assert.AreEqual(401, data.StatusCode);
        }
    }
}