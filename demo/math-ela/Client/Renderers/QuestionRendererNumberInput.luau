local M = {}

function M.render(question: any): { [string]: any }
	local content = question.content or {}
	local prompt = question.prompt or content.prompt or "Enter your answer"
	return {
		kind = "number_input",
		prompt = prompt,
		correctAnswer = content.correctAnswer,
		acceptedFormats = content.acceptedFormats or {},
		unit = content.unit,
		expectedTimeMs = question.expectedTimeMs,
		meta = { skillId = question.skillId, difficulty = question.difficulty, questionId = question.id },
	}
end

return M

