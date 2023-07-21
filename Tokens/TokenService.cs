using System.Text;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Net;
using AuthorizationCodeFlow.Tokens.Models;

namespace AuthorizationCodeFlow.Tokens;

public class TokenService
{
    private const string AUTHORIZE_URL = "https://dev-aedm5wf4pt51z7gs.us.auth0.com/authorize";
    private const string LOGIN_URL = "https://dev-aedm5wf4pt51z7gs.us.auth0.com/u/login";
    private const string REDIRECT_URL = "http://localhost:4200/";
    private const string TOKEN_URL = "https://dev-aedm5wf4pt51z7gs.us.auth0.com/oauth/token";

    private const string SCOPE = "openid+profile+email";

    private readonly HttpClient _httpClient;
    private readonly Credentials _credentials;

    public TokenService(HttpClient httpClient, Credentials credentials)
    {
        _httpClient = httpClient;
        _credentials = credentials;
    }

    public async Task<string> GetAccessTokenAsync()
    {
        var (codeVerifier, codeChallenge) = GenerateCodeChallengeAndVerifier();

        var state = await SendAuthorizeCodeRequestAsync(codeChallenge);
        var code = await LoginAsync(state);
        var tokens = await GetTokensAsync(code, codeVerifier);

        return tokens.AccessToken;
    }

    private async Task<string> SendAuthorizeCodeRequestAsync(string codeChallenge)
    {
        var authnUri = AUTHORIZE_URL +
          $"?client_id={_credentials.ClientId}" +
          $"&code_challenge={codeChallenge}" +
          "&code_challenge_method=S256" +
          $"&redirect_uri={Uri.EscapeDataString(REDIRECT_URL)}" +
          "&response_type=code" +
          $"&state={Guid.NewGuid()}" +
          $"&scope={SCOPE}";

        var authnResponse = await _httpClient.GetAsync(authnUri);
        authnResponse.EnsureSuccessStatusCode();
        var responseString = await authnResponse.Content.ReadAsStringAsync();

        // retrieve state which is used to prevent CSRF
        var pattern = @"<input\s+type=""hidden""\s+name=""state""\s+value=""(.*?)""\s*/>";
        var match = Regex.Match(responseString, pattern);
        if (!match.Success)
        {
            throw new Exception("Hidden state input not found in html.");
        }

        var state = match.Groups[1].Value;
        return state;
    }

    private async Task<string> LoginAsync(string state)
    {
        var loginUrl = LOGIN_URL + $"?state={state}";
        var authnPayload = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["state"] = state,
            ["username"] = _credentials.Username,
            ["password"] = _credentials.Password,
            ["action"] = "default"
        });

        var postResponse = await _httpClient.PostAsync(loginUrl, authnPayload);
        // HttpClient by default follows redirects, but in this example
        // it's redirected from HTTPS to HTTP (our localhost SPA) and in that case redirects are not followed
        if (postResponse.StatusCode != HttpStatusCode.Redirect)
        {
            throw new Exception("Unable to get redirect url: response status code was not a 302.");
        }

        var code = ExtractCodeFromUriQueryParameter(postResponse.Headers.Location);
        return code;
    }

    private async Task<TokenResponse> GetTokensAsync(string code, string codeVerifier)
    {
        var tokenPayload = new StringContent(
            $"client_id={_credentials.ClientId}" +
            $"&redirect_uri={Uri.EscapeDataString(REDIRECT_URL)}" +
            "&grant_type=authorization_code" +
            $"&code_verifier={codeVerifier}" +
            $"&code={code}",
            Encoding.UTF8,
            "application/x-www-form-urlencoded");

        var tokenResponse = await _httpClient.PostAsync(TOKEN_URL, tokenPayload);
        tokenResponse.EnsureSuccessStatusCode();

        var tokenResponseDeserialized = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>()
            ?? throw new Exception("Unable to get token: invalid response");
        return tokenResponseDeserialized;
    }

    private static (string codeVerifier, string codeChallenge) GenerateCodeChallengeAndVerifier()
    {
        var randomGen = RandomNumberGenerator.Create();

        var bytes = new byte[32];
        randomGen.GetBytes(bytes);
        var codeVerifier = Base64UrlEncode(Convert.ToBase64String(bytes));

        var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        var codeChallenge = Base64UrlEncode(Convert.ToBase64String(challengeBytes));

        return (codeVerifier, codeChallenge);
    }

    private static string Base64UrlEncode(string input) => input
        .Replace('+', '-')
        .Replace('/', '_')
        .Replace("=", "");

    private static string ExtractCodeFromUriQueryParameter(Uri? location)
    {
        var codeParameter = location?.Query
           .TrimStart('?')
           .Split('&')
           .FirstOrDefault(param => param.StartsWith("code="));

        return codeParameter?.Remove(0, "code=".Length)
            ?? throw new Exception("Response did not return a code.");
    }
}
