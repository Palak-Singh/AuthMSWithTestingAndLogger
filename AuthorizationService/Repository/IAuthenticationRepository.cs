using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthorizationService.Repository
{
    public interface IAuthenticationRepository
    {
        bool Authentication(string name, string password);

    }
}
