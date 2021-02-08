using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthorizationService.Models
{
    public static class Helper
    {
        public static readonly List<User> users = new List<User> {
            new User { UserId=1,Name="Harry",Password="123pass"},
            new User { UserId=2,Name="Roy",Password="pass123"}
        };
    }
}
