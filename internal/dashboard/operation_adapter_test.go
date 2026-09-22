package dashboard

func beginTestOperation(model *sandboxTUIModel, action, name, progress string, selectResult bool) tuiOperationOwner {
	owner, ok := model.tuiOperationState.Begin(action, name, selectResult)
	if !ok {
		panic("test operation was not admitted")
	}
	if progress != "" {
		model.tuiOperationState.SetProgress(owner, progress)
	}
	return owner
}

func resetTestOperation(model *sandboxTUIModel) {
	model.tuiOperationState = tuiOperationState{}
}
