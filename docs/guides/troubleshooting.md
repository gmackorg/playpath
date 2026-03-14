# Troubleshooting

## `HTTP requests are not enabled`

Enable HTTP in Roblox Studio or your published experience security settings.

## `SDK_NOT_INITIALIZED`

Call `PlayPath.init()` exactly once before any session or static API method.

## `UNAUTHORIZED`

Check:

- `gameKeyId`
- `apiKeySecret`
- `baseUrl`
- system clock drift

Use `PlayPath.getServerTime()` to compare drift if signatures appear valid but requests still fail.

## `RATE_LIMITED`

The SDK already retries retryable responses. If you keep hitting `429`:

- reduce event spam
- batch non-critical telemetry
- respect the current environment limits

## `SESSION_ENDED` or `PLAYER_LEFT`

Do not reuse ended sessions. Create a new session after a player rejoins or a new gameplay run begins.

## `No active session` in the demo

The demo expects `startSession` first. In Studio, re-run:

```lua
_G.DemoCommands.startMath()
```

or:

```lua
_G.DemoCommands.startELA()
```

## Pairing succeeds but profile looks stale

Re-check the profile with `session:getProfile()` or `PlayPath.getProfile(profileId)` after link completion. Treat linking and profile display as separate reads.

## Standards or profile endpoints unavailable

Read `PlayPath.getCapabilities()` and gate optional UX on the returned feature flags.

## Question type is unsupported in your client

Do not hard-fail the game flow. Render a fallback panel, log the unknown type, and offer skip while you add a renderer.

## Debugging checklist

1. Turn `logLevel` to `debug`.
2. Verify session creation succeeds.
3. Verify the question request payload includes expected `skill` and `context`.
4. Verify answer and telemetry payloads include `questionId`.
5. Capture `requestId` on failures for support escalation.
