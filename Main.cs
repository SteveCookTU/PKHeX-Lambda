using System;
using System.IO;
using System.Net;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using PKHeX.Core;
using System.Linq;
using Org.BouncyCastle.Crypto;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace PKHeXLambda
{
    public delegate byte[] ConvertEKXToSignedResponse(byte[] EKX);
    public class Functions
    {
        /// <summary>
        /// Local testing
        /// </summary>
        static void Main(string[] args) {
            var base64EKX = args.Length == 0 ? "" : args[0];
            Console.WriteLine(base64EKX + "\n-----");
            var bytes = StringToByteArray(base64EKX);
            var body = Convert.ToBase64String(ConvertEKXToSignedResponse(bytes));
            Console.WriteLine(body);
        }

        static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        /// <summary>
        /// Creates a signed JSON from a base 64 encoded EKX
        /// </summary>
        static private byte[] ConvertEKXToSignedResponse(byte[] EKX) {
            byte[] data = new byte[EKX.Length];
            Array.Copy(EKX, data, EKX.Length);
            PokeCrypto.DecryptIfEncrypted67(ref data);
            Array.Resize(ref data, 0x104);
            var PKM = PKMConverter.GetPKMfromBytes(data);
            var legalityAnalysis = new LegalityAnalysis(PKM);
            bool isLegal = legalityAnalysis.Report(false) == "Legal!";
            if (!isLegal)
            {
                return new byte[] { 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x96 };
            } else
            {
                byte[] header = { 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
                byte[] response = header.Concat(SignData(EKX)).ToArray();
                return response;
            }
        }

        /// <summary>
        /// Signs a string given to it
        /// </summary>
        static private byte[] SignData(byte[] data) {
            var sha1 = new SHA1Managed();
            var hash = sha1.ComputeHash(data);
            // This should be replaced with Secrets Manager
            string pem = Environment.GetEnvironmentVariable("PRIVATE_KEY").Replace("\\n", "\n").Trim();
            var pr = new PemReader(new StringReader(pem));
            var KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
            var rsa = new RSACryptoServiceProvider();
            
            rsa.ImportParameters(rsaParams);

            var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);

            rsaFormatter.SetHashAlgorithm("SHA1");

            return rsaFormatter.CreateSignature(hash);
        }


        /// <summary>
        /// Lambda function to respond to HTTP methods from API Gateway
        /// </summary>
        static private APIGatewayProxyResponse ConvertEKXAsLambda(APIGatewayProxyRequest request, ILambdaContext context, ConvertEKXToSignedResponse ConvertEKX)
        {
            var response = new APIGatewayProxyResponse
            {
                StatusCode = (int)HttpStatusCode.BadRequest,
                Body = "",
                Headers = new Dictionary<string, string> { { "Content-Type", "application/octet-stream" } },
                IsBase64Encoded = true
            };

            if (String.IsNullOrEmpty(request.Body)) return response;

            var requestBody = request.IsBase64Encoded ? Convert.FromBase64String(request.Body) : Encoding.UTF8.GetBytes(request.Body);
            if (requestBody.Length < 0x104) return response;

            var EKX = requestBody[(requestBody.Length - 0x104)..];

            if (EKX.Length == 0) return response;

            var body = ConvertEKX(EKX);

            response.Body = Convert.ToBase64String(body);
            response.StatusCode = (int)HttpStatusCode.OK;

            return response;
        }

        /// <summary>
        /// Lambda function to respond to HTTP methods from API Gateway with a signed EKX
        /// </summary>
        public APIGatewayProxyResponse ParseAndSignEKX(APIGatewayProxyRequest request, ILambdaContext context) {
            return ConvertEKXAsLambda(request, context, ConvertEKXToSignedResponse);
        }
    }
}
