using AuthorizationCodeFlow.Tokens;
using AuthorizationCodeFlow.Tokens.Models;

var httpClientHandler = new HttpClientHandler
{
    AllowAutoRedirect = true,
};

using var httpClient = new HttpClient(httpClientHandler);

var tokenService = new TokenService(
    httpClient,
    new Credentials(
        ClientId: "aHXUcUpNjC1VcFG3W4KZ6WjaVV2MRImN",
        Username: "test@example.com",
        Password: "Password1!")
);

var accessToken = await tokenService.GetAccessTokenAsync();
Console.WriteLine(accessToken);

Console.WriteLine("Press any key to close");
Console.ReadKey();