using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace AutoUpdaterDotNET
{
    /// <summary>
    /// Authentication class including domain details.
    /// </summary>
    class DomainAuthentication : NetworkAuthentication, IAuthentication
    {
        /// <summary>
        /// The Active Directory domain the user belongs to.
        /// </summary>
        public string Domain { get; set; }
        
        public DomainAuthentication(string username, string password, string domain) : base (username, password)
        {
            Domain = !string.IsNullOrEmpty(domain.Trim()) ? Environment.GetEnvironmentVariable("userdomain") : domain;
        }

        public new void Apply(ref MyWebClient webClient)
        {
            webClient.Credentials = new NetworkCredential(Username, Password, Domain);
        }
    }
}
