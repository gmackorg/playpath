local M = {}

local MATH_SKILLS = {
	"math.fractions",
	"math.fractions.addition",
	"math.fractions.comparison",
	"math.angles",
	"math.numberline",
}

local function getContextFromStudent(student: any): { [string]: any }?
	if student == nil or type(student) ~= "table" then
		return nil
	end

	local config = student.config
	if type(config) ~= "table" then
		return nil
	end

	if type(config.interests) == "table" and #config.interests > 0 then
		return { theme = config.theme, interests = config.interests, difficultyRange = config.difficultyRange }
	end

	return nil
end

function M.buildQuestionRequest(state: { mode: string, focusSkills: { string } }, requestId: string)
	local skills = state.focusSkills
	local skillToRequest = skills and skills[1]
	if skillToRequest == nil then
		skillToRequest = MATH_SKILLS[((tick() * 1000) % #MATH_SKILLS) + 1]
	end

	return {
		requestId = requestId,
		skill = skillToRequest,
		context = {
			theme = "math",
			domain = "math",
			requestId = requestId,
		},
	}
end

function M.selectDifficulty(state: { difficultyIndex: number? }, baseDifficulty: number?)
	if type(baseDifficulty) == "number" then
		return baseDifficulty
	end

	if type(state.difficultyIndex) == "number" then
		return state.difficultyIndex % 10 + 1
	end

	return 3
end

function M.normalizeContext(student: any?): { [string]: any }?
	if student == nil or type(student) ~= "table" then
		return nil
	end
	return getContextFromStudent(student)
end

return M
