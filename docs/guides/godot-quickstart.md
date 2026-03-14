# Godot Quickstart — PlayPath Play API

This guide covers integrating the PlayPath Play API into a Godot project using
GDScript and the `HTTPRequest` node. It assumes you have a game key pair from
the PlayPath dashboard.

## Prerequisites

- Godot 4.x
- A PlayPath game key ID and API key secret

## HMAC Signing

All Play API requests require HMAC-SHA256 authentication. Create an autoload
script for signing.

```gdscript
# playpath_auth.gd — add as an Autoload named "PlayPathAuth"
extends Node

var game_key_id: String = ""
var api_key_secret: String = ""
var base_url: String = "https://play.gmac.io"


func init(key_id: String, secret: String, url: String = "https://play.gmac.io") -> void:
	game_key_id = key_id
	api_key_secret = secret
	base_url = url


func _body_hash(body: String) -> String:
	var ctx := HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	ctx.update(body.to_utf8_buffer())
	return ctx.finish().hex_encode()


func compute_signature(method: String, pathname: String, body: String) -> Dictionary:
	var timestamp := str(int(Time.get_unix_time_from_system() * 1000))
	var nonce := _uuid4()
	var body_hash := _body_hash(body)
	var canonical := "%s:%s:%s:%s:%s" % [timestamp, nonce, method.to_upper(), pathname, body_hash]

	var hmac_ctx := HMACContext.new()
	hmac_ctx.start(HashingContext.HASH_SHA256, api_key_secret.to_utf8_buffer())
	hmac_ctx.update(canonical.to_utf8_buffer())
	var signature := "sha256=" + hmac_ctx.finish().hex_encode()

	return {
		"X-API-Key": game_key_id,
		"X-Timestamp": timestamp,
		"X-Nonce": nonce,
		"X-Signature": signature,
		"Content-Type": "application/json",
	}


func _uuid4() -> String:
	var rng := RandomNumberGenerator.new()
	rng.randomize()
	var hex := ""
	for i in 16:
		hex += "%02x" % rng.randi_range(0, 255)
	return "%s-%s-%s-%s-%s" % [
		hex.substr(0, 8),
		hex.substr(8, 4),
		"4" + hex.substr(13, 3),
		hex.substr(16, 4),
		hex.substr(20, 12),
	]
```

## HTTP Client

Create a helper that uses Godot's `HTTPRequest` node with HMAC headers.

```gdscript
# playpath_client.gd
extends Node

signal request_completed(result: Dictionary)

var _http: HTTPRequest


func _ready() -> void:
	_http = HTTPRequest.new()
	add_child(_http)


func send_request(method: String, path: String, body: String = "") -> Dictionary:
	var headers_dict := PlayPathAuth.compute_signature(method, path, body)
	var headers: PackedStringArray = []
	for key in headers_dict:
		headers.append("%s: %s" % [key, headers_dict[key]])

	var url := PlayPathAuth.base_url + path
	var http_method := HTTPClient.METHOD_POST if method == "POST" else HTTPClient.METHOD_GET

	_http.request(url, headers, http_method, body)

	var response = await _http.request_completed
	# response: [result, response_code, headers, body]
	var response_body: String = response[3].get_string_from_utf8()
	var parsed: Dictionary = JSON.parse_string(response_body)

	if response[1] < 200 or response[1] >= 300:
		push_error("PlayPath API error %d: %s" % [response[1], response_body])

	return parsed if parsed != null else {}
```

## Play Session Loop

Here is a complete session lifecycle in a game scene script.

```gdscript
# play_session.gd
extends Node

@export var game_key_id: String = "your-game-key-id"
@export var api_key_secret: String = "your-api-secret"
@export var profile_id: String = "prof_abc123"

var client: Node
var session_id: String = ""


func _ready() -> void:
	PlayPathAuth.init(game_key_id, api_key_secret)

	client = preload("res://playpath_client.gd").new()
	add_child(client)

	run_session()


func run_session() -> void:
	# 1. List available blueprints
	var blueprints := await client.send_request(
		"GET", "/api/v1/play/blueprints?profileId=%s" % profile_id)
	print("Blueprints: ", blueprints)

	if blueprints.get("blueprints", []).is_empty():
		push_error("No blueprints available")
		return

	var blueprint_id: String = blueprints["blueprints"][0]["id"]

	# 2. Start play session
	var start_body := JSON.stringify({
		"blueprintId": blueprint_id,
		"profileId": profile_id,
	})
	var session := await client.send_request(
		"POST", "/api/v1/play/start", start_body)
	print("Session started: ", session)

	session_id = session.get("sessionId", "")
	var challenges: Array = session.get("challenges", [])
	var world: Dictionary = session.get("world", {})

	# The world payload contains zones, entities, NPCs — render your game here
	print("World zones: ", world.get("zones", []).size())
	print("Challenges: ", challenges.size())
	print("Story: ", session.get("storyArc", {}).get("title", ""))

	# 3. Challenge loop
	for challenge in challenges:
		await run_challenge(challenge["id"])

	# 4. Complete session
	var summary := await client.send_request(
		"POST", "/api/v1/play/%s/complete" % session_id, "{}")
	print("Session summary: ", summary)
	print("Accuracy: ", summary.get("summary", {}).get("accuracy", 0))


func run_challenge(challenge_id: String) -> void:
	var path_prefix := "/api/v1/play/%s" % session_id

	# Start challenge (records begin time)
	var start_body := JSON.stringify({"challengeId": challenge_id})
	await client.send_request(
		"POST", "%s/challenge/start" % path_prefix, start_body)

	# (In a real game, present the challenge UI and wait for player input)
	await get_tree().create_timer(1.0).timeout

	# Submit answer
	var respond_body := JSON.stringify({
		"challengeId": challenge_id,
		"response": "b",
		"responseTimeMs": 1000,
		"hintUsed": false,
		"idempotencyKey": PlayPathAuth._uuid4(),
	})
	var grade := await client.send_request(
		"POST", "%s/challenge/respond" % path_prefix, respond_body)

	print("Challenge %s: correct=%s, mastery=%s" % [
		challenge_id,
		str(grade.get("correct", false)),
		str(grade.get("masteryLevel", 0)),
	])
```

## Telemetry

Track events by batching them and flushing periodically.

```gdscript
# telemetry_batcher.gd
extends Node

var _client: Node
var _session_id: String
var _pending: Array[Dictionary] = []
var _flush_threshold: int = 10
var _flush_timer: Timer


func init(client_node: Node, sid: String) -> void:
	_client = client_node
	_session_id = sid
	_flush_timer = Timer.new()
	_flush_timer.wait_time = 5.0
	_flush_timer.timeout.connect(_on_flush_timer)
	add_child(_flush_timer)
	_flush_timer.start()


func track(event_type: String, data: Dictionary = {}) -> void:
	_pending.append({
		"type": event_type,
		"timestamp": int(Time.get_unix_time_from_system() * 1000),
		"data": data,
		"idempotencyKey": PlayPathAuth._uuid4(),
	})
	if _pending.size() >= _flush_threshold:
		flush()


func flush() -> void:
	if _pending.is_empty():
		return
	var events := _pending.duplicate()
	_pending.clear()
	var body := JSON.stringify({"events": events})
	await _client.send_request(
		"POST", "/api/v1/play/%s/telemetry" % _session_id, body)


func _on_flush_timer() -> void:
	flush()
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

Check the `error` key in parsed responses:

```gdscript
var result := await client.send_request("POST", path, body)
if result.has("error"):
    var err = result["error"]
    push_error("PlayPath error [%s]: %s" % [err["code"], err["message"]])
```

See [PLAY_API.md](../../PLAY_API.md) for the full error code reference.

## Next Steps

- Read the full [Play API Reference](../../PLAY_API.md) for all endpoints.
- Review the [Event Model](../../EVENT_MODEL.md) for telemetry best practices.
- Keep `api_key_secret` server-side only. For multiplayer games, proxy API
  calls through your game server rather than calling from the client.
