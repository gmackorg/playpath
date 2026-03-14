local M = {}

function M.render(question: any): { [string]: any }
	local content = question.content or {}
	local prompt = question.prompt or content.prompt or "Place your answer on the number line"
	return {
		kind = "number_line",
		prompt = prompt,
		range = content.range,
		divisions = content.divisions,
		tolerance = content.tolerance,
		correctAnswer = content.correctAnswer,
		expectedTimeMs = question.expectedTimeMs,
		meta = { skillId = question.skillId, difficulty = question.difficulty, questionId = question.id },
	}
end

return M

