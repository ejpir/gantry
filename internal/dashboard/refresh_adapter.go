package dashboard

import "github.com/ejpir/gantry/internal/dashboard/refreshstate"

type tuiRefreshOwner = refreshstate.Owner
type tuiRefreshState = refreshstate.State

func newTUIRefreshState() tuiRefreshState { return refreshstate.New() }
