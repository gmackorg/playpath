local M = {}

function M.render(question: any): { [string]: any }
	local content = question.content or {}
	local prompt = question.prompt or content.prompt or "Measure the angle"
	return {
		kind = "angle_input",
		prompt = prompt,
		visual = content.visual or {},
		tolerance = content.tolerance,
		expectedTimeMs = question.expectedTimeMs,
		meta = { skillId = question.skillId, difficulty = question.difficulty, questionId = question.id },
	}
end

return M

