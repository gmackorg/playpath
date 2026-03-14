--!strict

local OpenApiV1 = {}

OpenApiV1.version = "v1"

OpenApiV1.paths = {
	time = "/api/v1/time",
	sessions = "/api/v1/sessions",
	questions = "/api/v1/questions",
	hints = "/api/v1/hints",
	events = "/api/v1/events",
	link = "/api/v1/link",
	unlink = "/api/v1/unlink",
	grades = "/api/v1/grades",
	standards = "/api/v1/standards",
	capabilities = "/api/v1/capabilities",
	profileBase = "/api/v1/profile",
}

function OpenApiV1.buildSessionPath(sessionId)
	return OpenApiV1.paths.sessions .. "/" .. sessionId
end

function OpenApiV1.buildQuestionPath(questionId)
	return OpenApiV1.paths.questions .. "/" .. questionId
end

function OpenApiV1.buildQuestionSkipPath(questionId)
	return OpenApiV1.buildQuestionPath(questionId) .. "/skip"
end

function OpenApiV1.buildProfilePath(profileId)
	return OpenApiV1.paths.profileBase .. "/" .. profileId
end

return OpenApiV1
