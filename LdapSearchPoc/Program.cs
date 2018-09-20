using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace LdapSearchPoc
{
    class Program
    {
        private static IDictionary<string, CertificateLookup> _certificateStore = new Dictionary<string, CertificateLookup>();

        static void Main(string[] args)
        {
            //string email = "test@test.se";
            string email = "enorocis.se.ediel@enoro.com";
            
            var certificateLookup = _certificateStore.ContainsKey(email) ? _certificateStore[email] : null;
            if (certificateLookup == null)
            {
                Console.Out.WriteLine($"Could not find a matching lookup for {email}, creating...");
                certificateLookup = new CertificateLookup();
                _certificateStore.Add(email, certificateLookup);
            }

            if (!certificateLookup.LastLookup.HasValue || certificateLookup.LastLookup.Value.CompareTo(DateTime.Now.AddHours(-1)) > 0)
            {
                Console.Out.WriteLine($"Lookup for {email} was outdated, refreshing!");
                GetCertificatesFromLdap(email, certificateLookup);
            }

        }

        private static void GetCertificatesFromLdap(string email, CertificateLookup certificateLookup)
        {
            string ldapHost = "sodir01.steria.se:389";
            Console.Out.WriteLine($"Searching for {email} on LDAP server {ldapHost}");
            using (var conn = new LdapConnection() { Constraints = new LdapConstraints { ReferralFollowing = true } })
            {
                
                conn.Connect(ldapHost, 389);
                                
                var results = conn.Search("c=se", LdapConnection.SCOPE_SUB, $"mail={email}", new[] { "usercertificate" }, false);

                HandleResults(results, certificateLookup, email);
            }
        }

        private static void HandleResults(LdapSearchResults results, CertificateLookup certificateLookup, string email)
        {
            if (results != null)
            {
                Console.Out.WriteLine($"Got {results.Count} matches for search for {email} user certificates");
                certificateLookup.LastLookup = DateTime.Now;
                while (results.HasMore())
                {
                    try
                    {
                        var result = results.FirstOrDefault();
                        if (result != null)
                        {
                            var certificate = result.getAttribute("userCertificate");
                            var certificates = GetCertificatesFromResult(email, certificate);
                            certificateLookup.CertificateCollection.AddRange(certificates.ToArray());
                        }
                    }
                    catch(InterThreadException interException)
                    {
                        Console.WriteLine($"Exception in HandleResults: {interException}");
                    }
                }

            }
        }

        private static IEnumerable<X509Certificate2> GetCertificatesFromResult(string email, LdapAttribute certificate)
        {
            for (int certificateIndex = 0; certificateIndex < certificate.ByteValueArray.Length; certificateIndex++)
            {
                X509Certificate2 cert1 = new X509Certificate2((byte[])(Array)certificate.ByteValueArray[certificateIndex]);                                
                Console.Out.WriteLine($"Added certificate no {certificateIndex + 1} for {email}");
                yield return cert1;
            }
        }

        private class CertificateLookup
        {
            public CertificateLookup()
            {
                CertificateCollection = new X509Certificate2Collection();
            }
            public DateTime? LastLookup { get; set; }
            public X509Certificate2Collection CertificateCollection { get; }
        }
    }
}
