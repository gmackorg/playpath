local Players = game:GetService("Players")
local HttpService = game:GetService("HttpService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local DemoReplicated = ReplicatedStorage:WaitForChild("PlayPathDemo")
local Remotes = require(DemoReplicated:WaitForChild("Remotes"))
local Renderer = require(script:WaitForChild("Renderers"):WaitForChild("QuestionRenderer"))
local CommandEvent = Remotes.CommandEvent
local ResponseEvent = Remotes.ResponseEvent
local StateEvent = Remotes.SessionStateEvent
local TelemetryEvent = Remotes.TelemetryEvent

local player = Players.LocalPlayer
local playerGui = player:WaitForChild("PlayerGui")
local sessionMode = "math"
local activeQuestion: any = nil
local currentQuestionStartAt = 0
local currentProfileId: string? = nil
local currentSkillId: string? = nil
local logLines = {} :: { string }

local uiRefs: {
	screenGui: ScreenGui,
	modeValue: TextLabel,
	sessionValue: TextLabel,
	statusValue: TextLabel,
	promptValue: TextLabel,
	metaValue: TextLabel,
	answerInput: TextBox,
	choiceContainer: Frame,
	logValue: TextLabel,
	submitButton: TextButton,
	autoButton: TextButton,
	hintButton: TextButton,
	skipButton: TextButton,
	startMathButton: TextButton,
	startELAButton: TextButton,
	capabilitiesButton: TextButton,
	profileButton: TextButton,
	standardsButton: TextButton,
	gradeButton: TextButton,
	endButton: TextButton,
}?

local function nextRequestId(): string
	return HttpService:GenerateGUID(false)
end

local function safeJson(value: any): string
	local ok, encoded = pcall(function()
		return HttpService:JSONEncode(value)
	end)
	if ok then
		return encoded
	end
	return tostring(value)
end

local function appendLog(message: string)
	table.insert(logLines, 1, message)
	while #logLines > 8 do
		table.remove(logLines)
	end
	if uiRefs then
		uiRefs.logValue.Text = table.concat(logLines, "\n")
	end
end

local function setStatus(text: string)
	if uiRefs then
		uiRefs.statusValue.Text = text
	end
	appendLog(text)
end

local function setSessionInfo(text: string)
	if uiRefs then
		uiRefs.sessionValue.Text = text
	end
end

local function coerceMode(mode: any): string
	if mode == "ela" then
		return "ela"
	end
	return "math"
end

local function sendCommand(action: string, payload: { [string]: any }?, mode: string?)
	local requestId = nextRequestId()
	CommandEvent:FireServer({
		action = action,
		requestId = requestId,
		mode = mode,
		payload = payload or {},
	})
	return requestId
end

local function nowMs(): number
	return os.clock() * 1000
end

local function sendTelemetry(eventType: string, eventPayload: { [string]: any })
	TelemetryEvent:FireServer({
		type = eventType,
		timestamp = nowMs(),
		data = eventPayload,
		properties = eventPayload,
	})
end

local function createLabel(parent: Instance, name: string, size: UDim2, position: UDim2, text: string, textSize: number, font: Enum.Font, textColor: Color3, alignX: Enum.TextXAlignment?): TextLabel
	local label = Instance.new("TextLabel")
	label.Name = name
	label.BackgroundTransparency = 1
	label.Size = size
	label.Position = position
	label.Text = text
	label.TextSize = textSize
	label.Font = font
	label.TextColor3 = textColor
	label.TextWrapped = true
	label.TextXAlignment = alignX or Enum.TextXAlignment.Left
	label.TextYAlignment = Enum.TextYAlignment.Top
	label.Parent = parent
	return label
end

local function createButton(parent: Instance, name: string, size: UDim2, position: UDim2, text: string, backgroundColor: Color3): TextButton
	local button = Instance.new("TextButton")
	button.Name = name
	button.Size = size
	button.Position = position
	button.BackgroundColor3 = backgroundColor
	button.TextColor3 = Color3.fromRGB(247, 242, 233)
	button.TextSize = 18
	button.Font = Enum.Font.GothamSemibold
	button.AutoButtonColor = true
	button.Text = text
	button.Parent = parent

	local corner = Instance.new("UICorner")
	corner.CornerRadius = UDim.new(0, 12)
	corner.Parent = button

	return button
end

local function clearChoiceButtons(parent: Frame)
	for _, child in ipairs(parent:GetChildren()) do
		if not child:IsA("UIListLayout") then
			child:Destroy()
		end
	end
end

local function choiceLabel(choice: any): string
	if type(choice) == "table" then
		if type(choice.text) == "string" then
			return choice.text
		end
		if type(choice.label) == "string" then
			return choice.label
		end
		if type(choice.id) == "string" then
			return choice.id
		end
	end
	return tostring(choice)
end

local function choiceAnswer(choice: any): any
	if type(choice) == "table" then
		if choice.id ~= nil then
			return choice.id
		end
		if choice.value ~= nil then
			return choice.value
		end
		if choice.text ~= nil then
			return choice.text
		end
	end
	return choice
end

local function createDemoGui()
	local existing = playerGui:FindFirstChild("PlayPathDemoGui")
	if existing then
		existing:Destroy()
	end

	local screenGui = Instance.new("ScreenGui")
	screenGui.Name = "PlayPathDemoGui"
	screenGui.ResetOnSpawn = false
	screenGui.IgnoreGuiInset = true
	screenGui.Parent = playerGui

	local root = Instance.new("Frame")
	root.Name = "Root"
	root.AnchorPoint = Vector2.new(0.5, 0.5)
	root.Position = UDim2.fromScale(0.5, 0.5)
	root.Size = UDim2.fromOffset(980, 620)
	root.BackgroundColor3 = Color3.fromRGB(31, 40, 47)
	root.Parent = screenGui

	local rootCorner = Instance.new("UICorner")
	rootCorner.CornerRadius = UDim.new(0, 22)
	rootCorner.Parent = root

	local rootStroke = Instance.new("UIStroke")
	rootStroke.Color = Color3.fromRGB(222, 164, 74)
	rootStroke.Thickness = 1.5
	rootStroke.Transparency = 0.15
	rootStroke.Parent = root

	local gradient = Instance.new("UIGradient")
	gradient.Color = ColorSequence.new({
		ColorSequenceKeypoint.new(0, Color3.fromRGB(47, 57, 65)),
		ColorSequenceKeypoint.new(1, Color3.fromRGB(24, 30, 35)),
	})
	gradient.Rotation = 135
	gradient.Parent = root

	local title = createLabel(
		root,
		"Title",
		UDim2.fromOffset(360, 40),
		UDim2.fromOffset(28, 22),
		"PlayPath Demo Studio",
		28,
		Enum.Font.Garamond,
		Color3.fromRGB(245, 236, 219)
	)
	title.TextYAlignment = Enum.TextYAlignment.Center

	local subtitle = createLabel(
		root,
		"Subtitle",
		UDim2.fromOffset(420, 36),
		UDim2.fromOffset(30, 62),
		"Math and ELA reference integration with a server-owned PlayPath boundary.",
		16,
		Enum.Font.Gotham,
		Color3.fromRGB(201, 196, 184)
	)

	local infoCard = Instance.new("Frame")
	infoCard.Name = "InfoCard"
	infoCard.Size = UDim2.fromOffset(286, 160)
	infoCard.Position = UDim2.fromOffset(28, 114)
	infoCard.BackgroundColor3 = Color3.fromRGB(42, 51, 59)
	infoCard.Parent = root

	local infoCorner = Instance.new("UICorner")
	infoCorner.CornerRadius = UDim.new(0, 16)
	infoCorner.Parent = infoCard

	local infoTitle = createLabel(
		infoCard,
		"InfoTitle",
		UDim2.fromOffset(240, 26),
		UDim2.fromOffset(18, 14),
		"Session Overview",
		18,
		Enum.Font.GothamSemibold,
		Color3.fromRGB(245, 236, 219)
	)

	createLabel(infoCard, "ModeLabel", UDim2.fromOffset(80, 20), UDim2.fromOffset(18, 52), "Mode", 13, Enum.Font.GothamBold, Color3.fromRGB(222, 164, 74))
	local modeValue = createLabel(infoCard, "ModeValue", UDim2.fromOffset(180, 20), UDim2.fromOffset(92, 52), "math", 14, Enum.Font.Gotham, Color3.fromRGB(245, 236, 219))

	createLabel(infoCard, "SessionLabel", UDim2.fromOffset(80, 38), UDim2.fromOffset(18, 76), "Session", 13, Enum.Font.GothamBold, Color3.fromRGB(222, 164, 74))
	local sessionValue = createLabel(infoCard, "SessionValue", UDim2.fromOffset(180, 38), UDim2.fromOffset(92, 76), "Waiting to start", 14, Enum.Font.Gotham, Color3.fromRGB(245, 236, 219))

	createLabel(infoCard, "StatusLabel", UDim2.fromOffset(80, 38), UDim2.fromOffset(18, 118), "Status", 13, Enum.Font.GothamBold, Color3.fromRGB(222, 164, 74))
	local statusValue = createLabel(infoCard, "StatusValue", UDim2.fromOffset(180, 38), UDim2.fromOffset(92, 118), "Ready", 14, Enum.Font.Gotham, Color3.fromRGB(194, 229, 202))

	local questionCard = Instance.new("Frame")
	questionCard.Name = "QuestionCard"
	questionCard.Size = UDim2.fromOffset(628, 372)
	questionCard.Position = UDim2.fromOffset(324, 22)
	questionCard.BackgroundColor3 = Color3.fromRGB(245, 240, 230)
	questionCard.Parent = root

	local questionCorner = Instance.new("UICorner")
	questionCorner.CornerRadius = UDim.new(0, 20)
	questionCorner.Parent = questionCard

	local promptValue = createLabel(
		questionCard,
		"PromptValue",
		UDim2.fromOffset(584, 110),
		UDim2.fromOffset(22, 24),
		"Waiting for the first question.",
		28,
		Enum.Font.Garamond,
		Color3.fromRGB(37, 42, 46)
	)

	local metaValue = createLabel(
		questionCard,
		"MetaValue",
		UDim2.fromOffset(560, 42),
		UDim2.fromOffset(24, 126),
		"Question metadata will appear here.",
		14,
		Enum.Font.Gotham,
		Color3.fromRGB(100, 93, 79)
	)

	local answerInput = Instance.new("TextBox")
	answerInput.Name = "AnswerInput"
	answerInput.Size = UDim2.fromOffset(584, 46)
	answerInput.Position = UDim2.fromOffset(22, 172)
	answerInput.BackgroundColor3 = Color3.fromRGB(255, 252, 247)
	answerInput.PlaceholderText = "Enter an answer or click an option below"
	answerInput.Text = ""
	answerInput.TextSize = 18
	answerInput.Font = Enum.Font.Gotham
	answerInput.TextColor3 = Color3.fromRGB(37, 42, 46)
	answerInput.ClearTextOnFocus = false
	answerInput.Parent = questionCard

	local inputCorner = Instance.new("UICorner")
	inputCorner.CornerRadius = UDim.new(0, 12)
	inputCorner.Parent = answerInput

	local choiceContainer = Instance.new("Frame")
	choiceContainer.Name = "ChoiceContainer"
	choiceContainer.Size = UDim2.fromOffset(584, 126)
	choiceContainer.Position = UDim2.fromOffset(22, 232)
	choiceContainer.BackgroundTransparency = 1
	choiceContainer.Parent = questionCard

	local choiceLayout = Instance.new("UIListLayout")
	choiceLayout.Padding = UDim.new(0, 8)
	choiceLayout.HorizontalAlignment = Enum.HorizontalAlignment.Left
	choiceLayout.Parent = choiceContainer

	local controlCard = Instance.new("Frame")
	controlCard.Name = "ControlCard"
	controlCard.Size = UDim2.fromOffset(924, 134)
	controlCard.Position = UDim2.fromOffset(28, 410)
	controlCard.BackgroundColor3 = Color3.fromRGB(42, 51, 59)
	controlCard.Parent = root

	local controlCorner = Instance.new("UICorner")
	controlCorner.CornerRadius = UDim.new(0, 16)
	controlCorner.Parent = controlCard

	createLabel(
		controlCard,
		"ControlTitle",
		UDim2.fromOffset(260, 24),
		UDim2.fromOffset(18, 14),
		"Interactive Controls",
		18,
		Enum.Font.GothamSemibold,
		Color3.fromRGB(245, 236, 219)
	)

	local startMathButton = createButton(controlCard, "StartMathButton", UDim2.fromOffset(126, 36), UDim2.fromOffset(18, 48), "Start Math", Color3.fromRGB(61, 120, 101))
	local startELAButton = createButton(controlCard, "StartELAButton", UDim2.fromOffset(126, 36), UDim2.fromOffset(154, 48), "Start ELA", Color3.fromRGB(109, 91, 149))
	local submitButton = createButton(controlCard, "SubmitButton", UDim2.fromOffset(126, 36), UDim2.fromOffset(290, 48), "Submit", Color3.fromRGB(196, 116, 58))
	local autoButton = createButton(controlCard, "AutoButton", UDim2.fromOffset(126, 36), UDim2.fromOffset(426, 48), "Auto Submit", Color3.fromRGB(191, 145, 64))
	local hintButton = createButton(controlCard, "HintButton", UDim2.fromOffset(126, 36), UDim2.fromOffset(562, 48), "Hint", Color3.fromRGB(86, 116, 164))
	local skipButton = createButton(controlCard, "SkipButton", UDim2.fromOffset(126, 36), UDim2.fromOffset(698, 48), "Skip", Color3.fromRGB(137, 83, 98))

	local capabilitiesButton = createButton(controlCard, "CapabilitiesButton", UDim2.fromOffset(126, 30), UDim2.fromOffset(18, 90), "Capabilities", Color3.fromRGB(64, 88, 112))
	local profileButton = createButton(controlCard, "ProfileButton", UDim2.fromOffset(126, 30), UDim2.fromOffset(154, 90), "Profile", Color3.fromRGB(64, 88, 112))
	local standardsButton = createButton(controlCard, "StandardsButton", UDim2.fromOffset(126, 30), UDim2.fromOffset(290, 90), "Standards", Color3.fromRGB(64, 88, 112))
	local gradeButton = createButton(controlCard, "GradeButton", UDim2.fromOffset(126, 30), UDim2.fromOffset(426, 90), "Submit Grade", Color3.fromRGB(64, 88, 112))
	local endButton = createButton(controlCard, "EndButton", UDim2.fromOffset(126, 30), UDim2.fromOffset(562, 90), "End Session", Color3.fromRGB(64, 88, 112))

	local logCard = Instance.new("Frame")
	logCard.Name = "LogCard"
	logCard.Size = UDim2.fromOffset(286, 254)
	logCard.Position = UDim2.fromOffset(28, 290)
	logCard.BackgroundColor3 = Color3.fromRGB(42, 51, 59)
	logCard.Parent = root

	local logCorner = Instance.new("UICorner")
	logCorner.CornerRadius = UDim.new(0, 16)
	logCorner.Parent = logCard

	createLabel(
		logCard,
		"LogTitle",
		UDim2.fromOffset(240, 24),
		UDim2.fromOffset(18, 14),
		"Live Event Log",
		18,
		Enum.Font.GothamSemibold,
		Color3.fromRGB(245, 236, 219)
	)

	local logValue = createLabel(
		logCard,
		"LogValue",
		UDim2.fromOffset(250, 200),
		UDim2.fromOffset(18, 44),
		"Waiting for activity...",
		14,
		Enum.Font.Code,
		Color3.fromRGB(205, 212, 201)
	)

	return {
		screenGui = screenGui,
		modeValue = modeValue,
		sessionValue = sessionValue,
		statusValue = statusValue,
		promptValue = promptValue,
		metaValue = metaValue,
		answerInput = answerInput,
		choiceContainer = choiceContainer,
		logValue = logValue,
		submitButton = submitButton,
		autoButton = autoButton,
		hintButton = hintButton,
		skipButton = skipButton,
		startMathButton = startMathButton,
		startELAButton = startELAButton,
		capabilitiesButton = capabilitiesButton,
		profileButton = profileButton,
		standardsButton = standardsButton,
		gradeButton = gradeButton,
		endButton = endButton,
	}
end

local function sendStartSession()
	if uiRefs then
		uiRefs.modeValue.Text = sessionMode
	end
	setStatus("Starting " .. string.upper(sessionMode) .. " session")
	sendCommand("startSession", {}, sessionMode)
end

local function sendQuestionRequest()
	setStatus("Requesting next question")
	sendCommand("requestQuestion", {}, sessionMode)
end

local function sendSkipQuestion()
	if activeQuestion == nil then
		setStatus("No active question to skip")
		return
	end
	sendCommand("skipQuestion", {
		questionId = activeQuestion.id,
		reason = "too_hard",
	}, sessionMode)
	sendTelemetry("question_skipped", {
		questionId = activeQuestion.id,
		reason = "too_hard",
	})
	setStatus("Skip requested")
end

local function sendHintRequest()
	if activeQuestion == nil then
		setStatus("No active question for hint request")
		return
	end
	sendCommand("requestHint", {
		questionId = activeQuestion.id,
		hintIndex = 0,
	}, sessionMode)
	sendTelemetry("hint_requested", {
		questionId = activeQuestion.id,
	})
	setStatus("Hint requested")
end

local function sendSubmit(answer: any)
	if activeQuestion == nil then
		setStatus("No active question to submit")
		return
	end
	local elapsed = nowMs() - currentQuestionStartAt
	sendCommand("submitAnswer", {
		questionId = activeQuestion.id,
		answer = answer,
		responseTimeMs = math.floor(elapsed),
		difficulty = activeQuestion.difficulty,
	}, sessionMode)
	setStatus("Submitting answer")
end

local function autoAnswerFromQuestion(question: any): any
	local questionContent = if type(question) == "table" then question else {}
	local content = if type(questionContent.content) == "table" then questionContent.content else {}
	local kind = questionContent.kind
	if kind == "multiple_choice" then
		local choices = questionContent.choices or content.options
		if type(choices) == "table" and #choices > 0 then
			return choiceAnswer(choices[1])
		end
		return "A"
	end
	if kind == "number_input" or kind == "number_line" then
		if questionContent.correctAnswer ~= nil then
			return questionContent.correctAnswer
		end
		if content.correctAnswer ~= nil then
			return content.correctAnswer
		end
		return 0
	end
	if kind == "fraction_visual" or kind == "angle_input" then
		if questionContent.correctAnswer ~= nil then
			return questionContent.correctAnswer
		end
		if content.correctAnswer ~= nil then
			return content.correctAnswer
		end
		return 0
	end
	return "auto"
end

local function sendAutoSubmit()
	if activeQuestion == nil then
		setStatus("No active question to auto-submit")
		return
	end
	local answer = autoAnswerFromQuestion(activeQuestion)
	if uiRefs then
		uiRefs.answerInput.Text = tostring(answer)
	end
	sendSubmit(answer)
end

local function setQuestionCard(view: { [string]: any }, rawQuestion: any)
	if not uiRefs then
		return
	end

	uiRefs.promptValue.Text = tostring(view.prompt or "No prompt available")
	uiRefs.answerInput.Text = ""
	uiRefs.answerInput.PlaceholderText = "Enter an answer or choose an option"
	uiRefs.metaValue.Text = string.format(
		"kind=%s  skill=%s  difficulty=%s",
		tostring(view.kind),
		tostring(view.meta and view.meta.skillId or rawQuestion.skillId or "n/a"),
		tostring(view.meta and view.meta.difficulty or rawQuestion.difficulty or "n/a")
	)

	clearChoiceButtons(uiRefs.choiceContainer)

	local choiceItems = view.choiceItems or view.options
	if type(choiceItems) == "table" and #choiceItems > 0 then
		for index, choice in ipairs(choiceItems) do
			local button = createButton(
				uiRefs.choiceContainer,
				"Choice_" .. tostring(index),
				UDim2.new(1, 0, 0, 34),
				UDim2.fromOffset(0, 0),
				string.format("%d. %s", index, choiceLabel(choice)),
				Color3.fromRGB(93, 108, 122)
			)
			button.MouseButton1Click:Connect(function()
				local answer = choiceAnswer(choice)
				uiRefs.answerInput.Text = tostring(answer)
				sendSubmit(answer)
			end)
		end
		return
	end

	local helperText = "Use the input field or Auto Submit for this question type."
	if view.kind == "fraction_visual" and type(view.visual) == "table" and view.visual.type ~= nil then
		helperText = "Visual type: " .. tostring(view.visual.type) .. ". Submit the matching value."
	elseif view.kind == "number_input" and type(view.acceptedFormats) == "table" and #view.acceptedFormats > 0 then
		helperText = "Accepted formats: " .. table.concat(view.acceptedFormats, ", ")
	end

	local helper = createLabel(
		uiRefs.choiceContainer,
		"HelperText",
		UDim2.new(1, 0, 0, 56),
		UDim2.fromOffset(0, 0),
		helperText,
		15,
		Enum.Font.Gotham,
		Color3.fromRGB(77, 88, 101)
	)
	helper.BackgroundColor3 = Color3.fromRGB(232, 225, 212)
	helper.BackgroundTransparency = 0
	local helperCorner = Instance.new("UICorner")
	helperCorner.CornerRadius = UDim.new(0, 12)
	helperCorner.Parent = helper
end

local function renderQuestion(rawQuestion: any)
	activeQuestion = rawQuestion
	currentQuestionStartAt = nowMs()
	currentSkillId = if type(rawQuestion) == "table" and type(rawQuestion.skillId) == "string" then rawQuestion.skillId else nil
	local view = Renderer.render(rawQuestion)
	setQuestionCard(view, rawQuestion)
	setStatus("Question ready: " .. tostring(view.kind))
	sendTelemetry("question_viewed", {
		questionId = view.meta and view.meta.questionId or rawQuestion.id,
		skillId = view.meta and view.meta.skillId or rawQuestion.skillId,
		difficulty = view.meta and view.meta.difficulty or rawQuestion.difficulty,
		questionType = rawQuestion.kind or view.kind,
	})
end

local function onSessionUpdate(message: { [string]: any })
	if message.type == "sessionStarted" then
		currentProfileId = if type(message.profileId) == "string" then message.profileId else nil
		if uiRefs then
			uiRefs.modeValue.Text = tostring(message.mode or sessionMode)
		end
		setSessionInfo(string.format("%s (%s)", tostring(message.sessionId), if message.linked then "linked" else "unlinked"))
		if message.pairingCode then
			setStatus("Session started. Pairing code: " .. tostring(message.pairingCode))
		else
			setStatus("Session started")
		end
		return
	end
	if message.type == "pairingResult" then
		setStatus("Pairing result: " .. tostring(message.success))
		return
	end
	setStatus("State update: " .. tostring(message.type))
end

local function handleResponse(response: { [string]: any })
	if response.ok ~= true then
		setStatus(string.format("Request failed: %s", tostring(response.payload and response.payload.error)))
		return
	end

	if response.action == "startSession" then
		sendQuestionRequest()
		return
	end

	if response.action == "requestQuestion" then
		local data = response.payload or {}
		if data.question then
			renderQuestion(data.question)
		elseif type(data.questions) == "table" and data.questions[1] ~= nil then
			renderQuestion(data.questions[1])
		else
			setStatus("Question response missing question payload")
		end
		return
	end

	if response.action == "submitAnswer" then
		local result = response.payload or {}
		setStatus(string.format("Answer result: correct=%s feedback=%s", tostring(result.correct), tostring(result.feedback)))
		sendTelemetry("answer", {
			questionId = activeQuestion and activeQuestion.id or nil,
			correct = result.correct,
		})
		sendQuestionRequest()
		return
	end

	if response.action == "requestHint" then
		local result = response.payload or {}
		setStatus(string.format("Hint %s: %s", tostring(result.hintIndex), tostring(result.hint)))
		return
	end

	if response.action == "skipQuestion" then
		setStatus("Question skipped")
		sendQuestionRequest()
		return
	end

	if response.action == "submitPairing" then
		setStatus("Pairing response: " .. tostring(response.payload and response.payload.success))
		return
	end

	if response.action == "getCapabilities" or response.action == "getStandards" or response.action == "getProfile" then
		setStatus(string.format("%s -> %s", tostring(response.action), safeJson(response.payload)))
		return
	end

	if response.action == "submitGrade" then
		setStatus(string.format("Grade submitted: %s / %s", tostring(response.payload and response.payload.status), tostring(response.payload and response.payload.reasonCode)))
		return
	end

	if response.action == "getSessionStatus" then
		setStatus("Session status: " .. safeJson(response.payload))
		return
	end

	if response.action == "endSession" then
		activeQuestion = nil
		currentSkillId = nil
		setSessionInfo("Session ended")
		if uiRefs then
			uiRefs.promptValue.Text = "Session ended. Start a new Math or ELA run."
			uiRefs.metaValue.Text = "No active question"
			uiRefs.answerInput.Text = ""
			clearChoiceButtons(uiRefs.choiceContainer)
		end
		setStatus("Session ended")
		return
	end
end

uiRefs = createDemoGui()
uiRefs.modeValue.Text = sessionMode
uiRefs.logValue.Text = "Waiting for activity..."

uiRefs.submitButton.MouseButton1Click:Connect(function()
	local answerText = uiRefs and uiRefs.answerInput.Text or ""
	if answerText == "" then
		setStatus("Enter an answer or choose an option")
		return
	end
	sendSubmit(answerText)
end)

uiRefs.autoButton.MouseButton1Click:Connect(sendAutoSubmit)
uiRefs.hintButton.MouseButton1Click:Connect(sendHintRequest)
uiRefs.skipButton.MouseButton1Click:Connect(sendSkipQuestion)
uiRefs.startMathButton.MouseButton1Click:Connect(function()
	sessionMode = "math"
	sendStartSession()
end)
uiRefs.startELAButton.MouseButton1Click:Connect(function()
	sessionMode = "ela"
	sendStartSession()
end)
uiRefs.capabilitiesButton.MouseButton1Click:Connect(function()
	sendCommand("getCapabilities", {}, sessionMode)
end)
uiRefs.profileButton.MouseButton1Click:Connect(function()
	if currentProfileId == nil then
		setStatus("No profile id available yet")
		return
	end
	sendCommand("getProfile", { profileId = currentProfileId }, sessionMode)
end)
uiRefs.standardsButton.MouseButton1Click:Connect(function()
	if currentSkillId == nil then
		setStatus("No skill id available for standards lookup")
		return
	end
	sendCommand("getStandards", { skillIds = { currentSkillId }, frameworkCode = "TEKS" }, sessionMode)
end)
uiRefs.gradeButton.MouseButton1Click:Connect(function()
	sendCommand("submitGrade", {
		score = 1,
		maxScore = 1,
		comment = "demo",
	}, sessionMode)
end)
uiRefs.endButton.MouseButton1Click:Connect(function()
	sendCommand("endSession", {}, sessionMode)
end)

StateEvent.OnClientEvent:Connect(function(state: { [string]: any })
	onSessionUpdate(state)
end)

ResponseEvent.OnClientEvent:Connect(handleResponse)

local DemoCommands = {
	start = sendStartSession,
	startMath = function()
		sessionMode = "math"
		if uiRefs then
			uiRefs.modeValue.Text = sessionMode
		end
		sendStartSession()
	end,
	startELA = function()
		sessionMode = "ela"
		if uiRefs then
			uiRefs.modeValue.Text = sessionMode
		end
		sendStartSession()
	end,
	requestQuestion = sendQuestionRequest,
	submit = sendSubmit,
	autoSubmit = sendAutoSubmit,
	skip = sendSkipQuestion,
	hint = sendHintRequest,
	endSession = function()
		sendCommand("endSession", {}, sessionMode)
	end,
	getCapabilities = function()
		sendCommand("getCapabilities", {}, sessionMode)
	end,
	getProfile = function(profileId: string)
		sendCommand("getProfile", { profileId = profileId }, sessionMode)
	end,
	getStandards = function(skillIds: { string }, frameworkCode: string?)
		sendCommand("getStandards", { skillIds = skillIds, frameworkCode = frameworkCode }, sessionMode)
	end,
	submitGrade = function(score: number, maxScore: number)
		sendCommand("submitGrade", {
			score = score,
			maxScore = maxScore,
			comment = "demo",
		}, sessionMode)
	end,
	setMode = function(mode: string)
		sessionMode = coerceMode(mode)
		if uiRefs then
			uiRefs.modeValue.Text = sessionMode
		end
	end,
}

_G.DemoCommands = DemoCommands
print("[PlayPath Demo] DemoCommands available on _G.DemoCommands")

task.delay(0.5, sendStartSession)
