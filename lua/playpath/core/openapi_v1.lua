return {
    paths = {
        time = "/api/v1/time",
        sessions = "/api/v1/sessions",
        worlds = "/api/v1/worlds",
        questions = "/api/v1/questions",
        hints = "/api/v1/hints",
        events = "/api/v1/events",
        playStart = "/api/v1/play/start",
        playBlueprints = "/api/v1/play/blueprints",
    },
    buildPlayChallengePath = function(sessionId, action)
        return "/api/v1/play/" .. sessionId .. "/challenge/" .. action
    end,
    buildPlayQuestPath = function(sessionId)
        return "/api/v1/play/" .. sessionId .. "/quest/complete"
    end,
    buildPlayDialogPath = function(sessionId)
        return "/api/v1/play/" .. sessionId .. "/dialog/advance"
    end,
    buildPlayNpcPath = function(sessionId)
        return "/api/v1/play/" .. sessionId .. "/npc/interact"
    end,
    buildPlayTelemetryPath = function(sessionId)
        return "/api/v1/play/" .. sessionId .. "/telemetry"
    end,
    buildPlayCompletePath = function(sessionId)
        return "/api/v1/play/" .. sessionId .. "/complete"
    end,
}
