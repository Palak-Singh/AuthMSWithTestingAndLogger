using AuthorizationService.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthorizationService.Repository
{
    public class AuthenticationRepository : IAuthenticationRepository
    { 
        //Check if user exist
        public bool Authentication(string name, string password)
        {
            var user = Helper.users.SingleOrDefault(u => u.Name == name && u.Password == password);
            if (user == null) return false;
            return true;          
        }
    }
}
