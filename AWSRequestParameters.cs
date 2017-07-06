using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AWS.API.Interfaces;
using AWS.API.Models;
using System.Security.Cryptography;
using System.Text;
using System.Net.Http;

namespace AWS.API.Services
{
    public class AWSRequestParameters
    {

        private string _accessKey = "";
        private string _secretKey = "/5Jkm8wt/cV2pCkOjlgg/xHv5dyO";
        private string _region = "";
        private string _service = "";

        private string _HTTPMethod = "";
        private string _canonicalURI = "";
        private string _canonicalQueryString = "";
        private string _canonicalHeaders = "";

        private string _dateTimeStamp, _dateOnlyStamp;

        public string AccessKey { get; set; }
        public string SecretKey { get; set; }
        public string Region { get; set; }
        public string Service { get; set; }
        public string HTTPMethod { get; set; }
        public string CanonicalURI { get; set; }
        public string CanonicalQueryString { get; set; }
        public string CanonicalHeaders { get; set; }
        public string DateTimeStamp { get; set; }
        
    }
}
