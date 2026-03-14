local M = {}

function M.render(question: any): { [string]: any }
	local content = question.content or {}
	local prompt = question.prompt or content.prompt or "Answer this question"
	local choices = question.choices or content.options
	if choices == nil or type(choices) ~= "table" then
		choices = {}
	end
	return {
		kind = "multiple_choice",
		prompt = prompt,
		choiceItems = choices,
		expectedTimeMs = question.expectedTimeMs,
		meta = { skillId = question.skillId, difficulty = question.difficulty, questionId = question.id },
	}
end

return M

