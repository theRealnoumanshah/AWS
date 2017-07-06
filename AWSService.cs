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
    public abstract class AWSService
    {

        private AWSRequestParameters _awsParams;
        private const string _authorizationHeaderScheme = "AWS4-HMAC-SHA256";

        public AWSService(AWSRequestParameters awsRequestParameters)
        {
            _awsParams = awsRequestParameters;

        }

        public async Task<string> Initialize()
        {
            string dateOnlyStamp;

            _awsParams.DateTimeStamp = getAWSDate(DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"));
            dateOnlyStamp = _awsParams.DateTimeStamp.Split('T')[0];

            // empty payload for GET request
            string payload = "",
                hashedPayload = "",
                canonicalRequestHash = "";

            using (var algorithm = SHA256.Create())
            {

                hashedPayload = toHexString(algorithm.ComputeHash(Encoding.UTF8.GetBytes(payload)));

            }

            string canonicalReq = getCanonicalRequest(hashedPayload.ToLower());

            using (var algorithm = SHA256.Create())
            {

                canonicalRequestHash = toHexString(algorithm.ComputeHash(Encoding.UTF8.GetBytes(canonicalReq)));

            }

            string stringToSign = "AWS4-HMAC-SHA256\n" +
                                  _awsParams.DateTimeStamp + "\n" +
                                  dateOnlyStamp + "/" + _awsParams.Region + "/" + _awsParams.Service + "/aws4_request\n" +
                                  canonicalRequestHash.ToLower();

            byte[] signingKey = getSignatureKey(_awsParams.SecretKey, dateOnlyStamp, _awsParams.Region, _awsParams.Service);

            string authorizationSignature = getAuthorizationSignature(stringToSign, signingKey);

            string authorizationHeaderParameter = getAuthorizationParameter(dateOnlyStamp, authorizationSignature.ToLower());

            var client = new HttpClient
            {
                BaseAddress = new Uri("http://glacier.us-east-1.amazonaws.com")
            };

            var authorizationHeader = new System.Net.Http.Headers.AuthenticationHeaderValue(_authorizationHeaderScheme, authorizationHeaderParameter);

            client.DefaultRequestHeaders.Authorization = authorizationHeader;
            client.DefaultRequestHeaders.Add("x-amz-date", _awsParams.DateTimeStamp);
            client.DefaultRequestHeaders.Add("x-amz-content-sha256", hashedPayload.ToLower());
            client.DefaultRequestHeaders.Add("x-amz-glacier-version", "2012-06-01");

            HttpResponseMessage response = await client.GetAsync(_awsParams.CanonicalURI);

            return await response.Content.ReadAsStringAsync();
        }

        private string getCanonicalRequest(string hashedPayload)
        {
            return   _awsParams.HTTPMethod + "\n" +
                                _awsParams.CanonicalURI + "\n" +
                                _awsParams.CanonicalQueryString + "\n" +
                                _awsParams.CanonicalHeaders + "\n" +
                                "x-amz-content-sha256:" + hashedPayload.ToLower() + "\n" +
                                "x-amz-date:" + _awsParams.DateTimeStamp + "\n" +
                                "\n" +
                                "host;x-amz-content-sha256;x-amz-date\n" +
                                hashedPayload.ToLower();
        }

        private string getAuthorizationParameter(string dateOnlyStamp, string authorizationSignature)
        {
            return "Credential=" +
                              _awsParams.AccessKey + "/" +
                              dateOnlyStamp + "/" +
                              _awsParams.Region + "/" +
                              _awsParams.Service + "/aws4_request," +
                              " SignedHeaders=host;x-amz-content-sha256;x-amz-date," +
                              " Signature=" + authorizationSignature;
        }

        private byte[] HmacSHA256(String data, byte[] key)
        {
            HMACSHA256 hmac = new HMACSHA256(key);
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        private byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName)
        {
            byte[] kSecret = Encoding.UTF8.GetBytes(("AWS4" + key).ToCharArray());
            byte[] kDate = HmacSHA256(dateStamp, kSecret);
            byte[] kRegion = HmacSHA256(regionName, kDate);
            byte[] kService = HmacSHA256(serviceName, kRegion);
            byte[] kSigning = HmacSHA256("aws4_request", kService);

            return kSigning;
        }

        private string getAuthorizationSignature(string stringToHash, byte[] signingKey)
        {
            string kAuthSig;

            using (HMACSHA256 hmac = new HMACSHA256(signingKey))
            {

                kAuthSig = toHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToHash)));

            }

            return kAuthSig;
        }

        // this function converts the generic JS ISO8601 date format to the specific format the AWS API wants
        private string getAWSDate(string dateStr)
        {
            dateStr = dateStr.Replace(":", "");
            dateStr = dateStr.Replace("-", "");

            dateStr = dateStr.Split('.')[0] + "Z";

            return dateStr;
        }

        private string toHexString(byte[] SHA256Result)
        {

            StringBuilder stringBuilder = new StringBuilder();

            foreach (byte b in SHA256Result)
                stringBuilder.AppendFormat("{0:X2}", b);

            return stringBuilder.ToString();

        }
    }
}
