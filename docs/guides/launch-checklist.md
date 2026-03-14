# Launch Checklist

Use this before handing the SDK integration to QA, production engineering, or an external studio partner.

## Installation and environment

- `PlayPath.init()` runs once on the server
- secrets are stored server-side only
- correct `baseUrl` is configured for beta or production
- HTTP is enabled in the experience

## Session lifecycle

- one active session per player
- `createSession()` on join or gameplay entry
- `endSession()` on `PlayerRemoving` and match/session end
- no reuse of ended session handles

## Core API loop

- `getNextQuestion()` returns normalized question data
- `submitAnswer()` works for correct and incorrect answers
- `getHint()` or `skipQuestion()` is reachable from gameplay
- `trackEvent()` sends `question_viewed`, `answer`, `hint_requested`, `question_skipped`, `session_end`

## Optional API surfaces

- `getCapabilities()` cached and respected
- `getProfile()` integrated if linking UI exists
- `getStandards()` only used when supported
- `submitGrade()` wired only when your environment expects grade passback

## Client/server architecture

- no PlayPath HTTP logic on the client
- client only sends intent and displays normalized question data
- unsupported question types fail soft

## Demo validation

- Math flow runs end-to-end
- ELA flow runs end-to-end
- mock mode smoke completed
- beta smoke completed with real credentials

## Documentation handoff

- integration team has followed one quickstart
- integration team has the API contract doc
- integration team has the troubleshooting guide
- any game-specific wrappers or conventions are documented locally
