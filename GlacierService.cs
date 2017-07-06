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
    public class GlacierService : AWSService
    {

        public GlacierService()
        {
            
        }
        private AWSRequestParameters _awsParams;

        private string access_key = "AKIAIKVQSDKOTXUOWDNA";
        private string secret_key = "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";
        private string region = "us-east-1";
        private string url = "glacier.us-east-1.amazonaws.com";
        private string myService = "glacier";
        private string myMethod = "GET";
        private string myPath = "/";

        // get the various date formats needed to form our request
        private string amazonDate, authDate;

        public void InitializeAWS()
        {
            amazonDate = getAWSDate(DateTime.Now.ToUniversalTime().ToString());
            authDate = amazonDate.Split('T')[0];

            // we have an empty payload here because it is a GET request
            string payload = "";
            string hashedPayload = "";
            string canonicalReqHash = "";
            // get the SHA256 hash value for our payload
            //string hashedPayload = crypto.SHA256(payload).toString();

            using (var algorithm = SHA256.Create())
            {
                // Create the at_hash using the access token returned by CreateAccessTokenAsync.
                hashedPayload = algorithm.ComputeHash(Encoding.ASCII.GetBytes(payload)).ToString();

            }

            // create our canonical request
            var canonicalReq = myMethod + "\n" +
                                myPath + "\n" +
                                "\n" +
                                "host:" + url + "\n" +
                                "x-amz-content-sha256:" + hashedPayload + "\n" +
                                "x-amz-date:" + amazonDate + "\n" +
                                "\n" +
                                "host;x-amz-content-sha256;x-amz-date" + "\n" +
                                hashedPayload;

            using (var algorithm = SHA256.Create())
            {
                // hash the canonical request
                canonicalReqHash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(canonicalReq)).ToString();

            }

            // form our String-to-Sign
            string stringToSign = "AWS4-HMAC-SHA256\n" +
                                amazonDate + "\n" +
                                authDate + "/" + region + "/" + myService + "/aws4_request\n" +
                                canonicalReqHash;
            // get our Signing Key
            string signingKey = getSignatureKey(secret_key, authDate, region, myService);

            // get our Auth Key
            string authKey = getSignatureKey(secret_key, authDate, region, myService);

            // Form our authorization header
            var authString = "AWS4-HMAC-SHA256 " +
                              "Credential=" +
                              access_key + "/" +
                              authDate + "/" +
                              region + "/" +
                              myService + "/aws4_request," +
                              "SignedHeaders=host;x-amz-content-sha256;x-amz-date," +
                              "Signature=" + authKey;

            //List<Post> posts = null;
            var client = new HttpClient
            {
                BaseAddress = new Uri("http://jsonplaceholder.typicode.com/posts/")
            };

            client.DefaultRequestHeaders.Add("Authorization", authString);
            client.DefaultRequestHeaders.Add("Host", url);
            client.DefaultRequestHeaders.Add("x-amz-date", amazonDate);
            client.DefaultRequestHeaders.Add("x-amz-content-sha256", hashedPayload);

            var response = client.GetAsync("");
            //var stream = await response.Content.ReadAsStreamAsync();
            //var serializer = new DataContractJsonSerializer(typeof(List<Post>));
            //posts = (List<Post>)serializer.ReadObject(stream);

        }


        // this function gets the Signature Key, see AWS documentation for more details
        private string getSignatureKey(string key, string dateStamp, string regionName, string serviceName)
        {
            byte[] kSigning;

            using (HMACSHA256 hmac = new HMACSHA256(Encoding.ASCII.GetBytes(key)))
            {

                byte[] kDate = hmac.ComputeHash(Encoding.ASCII.GetBytes(dateStamp + "AWS4" + key));
                byte[] kRegion = hmac.ComputeHash(Encoding.ASCII.GetBytes(regionName + kDate));
                byte[] kService = hmac.ComputeHash(Encoding.ASCII.GetBytes(serviceName + kRegion));
                kSigning = hmac.ComputeHash(Encoding.ASCII.GetBytes("aws4_request"+ kService));

            }


            return kSigning.ToString();
        }

        // this function gets the Signature Key, see AWS documentation for more details
        private string getAuthKey(string stringToHash, string signingKey)
        {
            byte[] kAuthKey;

            using (HMACSHA256 hmac = new HMACSHA256(Encoding.ASCII.GetBytes(signingKey)))
            {

                kAuthKey = hmac.ComputeHash(Encoding.ASCII.GetBytes(stringToHash));
              
            }

            return kAuthKey.ToString();
        }

        public List<GlacierDetail> GetVaultDetails()
        {
            GlacierDetail details = new GlacierDetail();
            details.Id = Guid.NewGuid().ToString();
            details.Name = "vault1";
            
            return new List<GlacierDetail>() { details };
        }

        // this function converts the generic JS ISO8601 date format to the specific format the AWS API wants
        private string getAWSDate(string dateStr)
        {           
            dateStr = dateStr.Replace(":", "");
            dateStr = dateStr.Replace("-", "");

            dateStr = dateStr.Split('.')[0] + "Z";

            return dateStr;
        }
    }
}
