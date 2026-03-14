local M = {}

function M.render(question: any): { [string]: any }
	local content = question.content or {}
	local prompt = question.prompt or content.prompt or "What fraction is shown?"
	return {
		kind = "fraction_visual",
		prompt = prompt,
		visual = content.visual or {},
		options = content.options or {},
		hints = question.hints,
		expectedTimeMs = question.expectedTimeMs,
		meta = { skillId = question.skillId, difficulty = question.difficulty, questionId = question.id },
	}
end

return M

