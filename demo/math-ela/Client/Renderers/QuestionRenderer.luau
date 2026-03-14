local multipleChoice = require(script:WaitForChild("QuestionRendererMultipleChoice"))
local numberInput = require(script:WaitForChild("QuestionRendererNumberInput"))
local fractionVisual = require(script:WaitForChild("QuestionRendererFractionVisual"))
local angleInput = require(script:WaitForChild("QuestionRendererAngleInput"))
local numberLine = require(script:WaitForChild("QuestionRendererNumberLine"))

local M = {}

function M.render(question: any): { [string]: any }
	local kind = if type(question) == "table" and type(question.kind) == "string" then question.kind else "unknown"

	if kind == "multiple_choice" then
		return multipleChoice.render(question)
	end
	if kind == "number_input" then
		return numberInput.render(question)
	end
	if kind == "fraction_visual" then
		return fractionVisual.render(question)
	end
	if kind == "angle_input" then
		return angleInput.render(question)
	end
	if kind == "number_line" then
		return numberLine.render(question)
	end

	return {
		kind = "unsupported",
		prompt = "This question type is not supported in demo yet.",
		meta = { questionId = if type(question) == "table" then question.id else nil },
	}
end

return M

