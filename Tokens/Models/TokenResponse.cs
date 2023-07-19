using System.Text.Json.Serialization;

namespace AuthorizationCodeFlow.Tokens.Models;

public record TokenResponse(
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("id_token")] string IdToken,
    [property: JsonPropertyName("scope")] string Scope);
