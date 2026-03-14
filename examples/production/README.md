# Production Example

This example is intentionally small. It shows the recommended server-owned wrapper shape that external studios should copy and adapt.

Primary file:

- [PlayPathGameService.lua](/Volumes/dev/roblox/playpath-sdk/examples/production/Server/PlayPathGameService.lua)

The sample service demonstrates:

- one-time SDK initialization
- one active session per player
- cached capabilities
- question request orchestration
- answer submission with `responseTimeMs`
- hint and skip handling
- session-end telemetry and cleanup

Studios should pair this with:

- their own RemoteEvent/RemoteFunction layer
- client-side question rendering
- game-specific routing for skills, contexts, and outcomes
