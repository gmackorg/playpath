local M = {}

local ELA_SKILLS = {
	"sor.phonological",
	"sor.phonics",
	"sor.fluency",
	"sor.vocabulary",
	"sor.comprehension",
}

local function getContextFromStudent(student: any): { [string]: any }?
	if student == nil or type(student) ~= "table" then
		return nil
	end

	local config = student.config
	if type(config) ~= "table" then
		return nil
	end

	return {
		theme = config.theme,
		interests = config.interests,
	}
end

function M.buildQuestionRequest(state: { mode: string, focusSkills: { string } }, requestId: string)
	local skills = state.focusSkills
	local skillToRequest = skills and skills[1]
	if skillToRequest == nil then
		skillToRequest = ELA_SKILLS[((tick() * 1000) % #ELA_SKILLS) + 1]
	end

	return {
		requestId = requestId,
		skill = skillToRequest,
		context = {
			theme = "ela",
			domain = "ela",
			requestId = requestId,
		},
	}
end

function M.normalizeContext(student: any?): { [string]: any }?
	if student == nil or type(student) ~= "table" then
		return nil
	end
	return getContextFromStudent(student)
end

function M.selectDifficulty(state: { difficultyIndex: number? }, baseDifficulty: number?)
	if type(baseDifficulty) == "number" then
		return baseDifficulty
	end

	if type(state.difficultyIndex) == "number" then
		return state.difficultyIndex % 10 + 1
	end

	return 2
end

return M
