--!strict
-- Shared remote definitions for the Math/ELA demo game.

local ReplicatedStorage = game:GetService("ReplicatedStorage")

local REMOTE_FOLDER_NAME = "PlayPathDemoRemotes"

local function ensureFolder(): Folder
	local folder = ReplicatedStorage:FindFirstChild(REMOTE_FOLDER_NAME)
	if folder == nil or not folder:IsA("Folder") then
		folder = Instance.new("Folder")
		folder.Name = REMOTE_FOLDER_NAME
		folder.Parent = ReplicatedStorage
	else
		folder = folder :: Folder
	end
	return folder
end

local function ensureRemote(parent: Instance, name: string, className: "RemoteEvent" | "RemoteFunction"): Instance
	local remote = parent:FindFirstChild(name)
	if remote ~= nil then
		if remote:IsA(className) then
			return remote
		else
			remote:Destroy()
		end
	end

	local created: Instance
	if className == "RemoteEvent" then
		created = Instance.new("RemoteEvent")
	else
		created = Instance.new("RemoteFunction")
	end
	created.Name = name
	created.Parent = parent
	return created
end

local folder = ensureFolder()

local remotes = {
	CommandEvent = ensureRemote(folder, "CommandEvent", "RemoteEvent") :: RemoteEvent,
	ResponseEvent = ensureRemote(folder, "ResponseEvent", "RemoteEvent") :: RemoteEvent,
	SessionStateEvent = ensureRemote(folder, "SessionStateEvent", "RemoteEvent") :: RemoteEvent,
	TelemetryEvent = ensureRemote(folder, "TelemetryEvent", "RemoteEvent") :: RemoteEvent,
}

return remotes
