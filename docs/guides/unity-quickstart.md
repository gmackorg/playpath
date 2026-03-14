# Unity Quickstart — PlayPath Play API

This guide covers integrating the PlayPath Play API into a Unity project using
C# and `HttpClient`. It assumes you have a game key pair from the PlayPath
dashboard.

## Prerequisites

- Unity 2021.3+ (LTS recommended)
- .NET Standard 2.1 or .NET Framework 4.x scripting backend
- A PlayPath game key ID and API key secret

## HMAC Signing

All Play API requests require HMAC-SHA256 authentication. Create a utility
class to handle signing.

```csharp
using System;
using System.Security.Cryptography;
using System.Text;

public static class PlayPathAuth
{
    public static string ComputeBodyHash(string body)
    {
        using var sha256 = SHA256.Create();
        byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(body));
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    public static string ComputeSignature(
        string apiKeySecret,
        string timestamp,
        string nonce,
        string method,
        string pathname,
        string body)
    {
        string bodyHash = ComputeBodyHash(body);
        string canonical = $"{timestamp}:{nonce}:{method.ToUpperInvariant()}:{pathname}:{bodyHash}";

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(apiKeySecret));
        byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical));
        return "sha256=" + BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    public static long GetTimestampMs()
    {
        return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }
}
```

## HTTP Client Setup

Create a client wrapper that adds auth headers to every request.

```csharp
using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using UnityEngine;

public class PlayPathClient
{
    private readonly HttpClient _http;
    private readonly string _gameKeyId;
    private readonly string _apiKeySecret;
    private readonly string _baseUrl;

    public PlayPathClient(string gameKeyId, string apiKeySecret,
        string baseUrl = "https://play.gmac.io")
    {
        _http = new HttpClient();
        _gameKeyId = gameKeyId;
        _apiKeySecret = apiKeySecret;
        _baseUrl = baseUrl;
    }

    public async Task<string> SendAsync(
        string method, string path, string jsonBody = "")
    {
        string timestamp = PlayPathAuth.GetTimestampMs().ToString();
        string nonce = Guid.NewGuid().ToString();
        string signature = PlayPathAuth.ComputeSignature(
            _apiKeySecret, timestamp, nonce, method, path, jsonBody);

        var request = new HttpRequestMessage(
            new HttpMethod(method), _baseUrl + path);

        request.Headers.Add("X-API-Key", _gameKeyId);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-Signature", signature);

        if (!string.IsNullOrEmpty(jsonBody))
        {
            request.Content = new StringContent(
                jsonBody, Encoding.UTF8, "application/json");
        }

        HttpResponseMessage response = await _http.SendAsync(request);
        string responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            Debug.LogError(
                $"PlayPath API error {response.StatusCode}: {responseBody}");
        }

        return responseBody;
    }
}
```

## Play Session Loop

Here is a complete session lifecycle: list blueprints, start a session,
run the challenge loop, and complete the session.

This example uses Unity's `JsonUtility` for simplicity. For production, consider
Newtonsoft.Json or System.Text.Json for full type coverage.

```csharp
using System;
using System.Threading.Tasks;
using UnityEngine;

public class PlayPathSession : MonoBehaviour
{
    [SerializeField] private string gameKeyId = "your-game-key-id";
    [SerializeField] private string apiKeySecret = "your-api-secret";
    [SerializeField] private string profileId = "prof_abc123";

    private PlayPathClient _client;
    private string _sessionId;

    async void Start()
    {
        _client = new PlayPathClient(gameKeyId, apiKeySecret);

        try
        {
            await RunPlaySession();
        }
        catch (Exception ex)
        {
            Debug.LogError($"PlayPath session failed: {ex.Message}");
        }
    }

    private async Task RunPlaySession()
    {
        // 1. List available blueprints
        string blueprintsJson = await _client.SendAsync(
            "GET", $"/api/v1/play/blueprints?profileId={profileId}");
        Debug.Log($"Blueprints: {blueprintsJson}");

        // Parse the first blueprint ID (use a proper JSON parser in production)
        string blueprintId = ParseBlueprintId(blueprintsJson);

        // 2. Start play session
        string startBody = JsonUtility.ToJson(new StartRequest
        {
            blueprintId = blueprintId,
            profileId = profileId
        });
        string startJson = await _client.SendAsync(
            "POST", "/api/v1/play/start", startBody);
        Debug.Log($"Session started: {startJson}");

        _sessionId = ParseSessionId(startJson);

        // 3. Challenge loop — iterate through challenges from the world payload
        string challengeId = ParseFirstChallengeId(startJson);
        if (challengeId != null)
        {
            await RunChallenge(challengeId);
        }

        // 4. Complete session
        string completeJson = await _client.SendAsync(
            "POST", $"/api/v1/play/{_sessionId}/complete", "{}");
        Debug.Log($"Session summary: {completeJson}");
    }

    private async Task RunChallenge(string challengeId)
    {
        // Start challenge (records begin time on server)
        string startBody = $"{{\"challengeId\":\"{challengeId}\"}}";
        await _client.SendAsync(
            "POST", $"/api/v1/play/{_sessionId}/challenge/start", startBody);

        // Simulate player answering after some time
        await Task.Delay(2000);

        // Submit answer
        string respondBody = JsonUtility.ToJson(new RespondRequest
        {
            challengeId = challengeId,
            response = "b",
            responseTimeMs = 2000,
            hintUsed = false,
            idempotencyKey = Guid.NewGuid().ToString()
        });
        string gradeJson = await _client.SendAsync(
            "POST", $"/api/v1/play/{_sessionId}/challenge/respond", respondBody);
        Debug.Log($"Challenge result: {gradeJson}");
    }

    // Minimal JSON parsing helpers (use a proper JSON library in production)
    private string ParseBlueprintId(string json) { /* ... */ return ""; }
    private string ParseSessionId(string json) { /* ... */ return ""; }
    private string ParseFirstChallengeId(string json) { /* ... */ return null; }

    [Serializable]
    private class StartRequest
    {
        public string blueprintId;
        public string profileId;
    }

    [Serializable]
    private class RespondRequest
    {
        public string challengeId;
        public string response;
        public int responseTimeMs;
        public bool hintUsed;
        public string idempotencyKey;
    }
}
```

## Telemetry

Track events by batching them and flushing periodically.

```csharp
using System;
using System.Collections.Generic;

public class TelemetryBatcher
{
    private readonly PlayPathClient _client;
    private readonly string _sessionId;
    private readonly List<string> _pending = new();
    private const int FlushThreshold = 10;

    public TelemetryBatcher(PlayPathClient client, string sessionId)
    {
        _client = client;
        _sessionId = sessionId;
    }

    public void Track(string type, string dataJson)
    {
        long ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        string key = Guid.NewGuid().ToString();
        _pending.Add(
            $"{{\"type\":\"{type}\",\"timestamp\":{ts}," +
            $"\"data\":{dataJson},\"idempotencyKey\":\"{key}\"}}");

        if (_pending.Count >= FlushThreshold)
            _ = Flush();
    }

    public async System.Threading.Tasks.Task Flush()
    {
        if (_pending.Count == 0) return;

        string events = string.Join(",", _pending);
        _pending.Clear();

        string body = $"{{\"events\":[{events}]}}";
        await _client.SendAsync(
            "POST", $"/api/v1/play/{_sessionId}/telemetry", body);
    }
}
```

## Error Handling

All API errors return a consistent JSON shape:

```json
{
  "error": {
    "code": "CHALLENGE_NOT_FOUND",
    "message": "Challenge ID not found in this blueprint"
  }
}
```

Check `HttpResponseMessage.StatusCode` and parse the error body to handle
specific codes. See [PLAY_API.md](../../PLAY_API.md) for the full error
code reference.

## Next Steps

- Read the full [Play API Reference](../../PLAY_API.md) for all endpoints.
- Review the [Event Model](../../EVENT_MODEL.md) for telemetry best practices.
- Keep `apiKeySecret` server-side only. In multiplayer games, proxy API calls
  through your game server.
