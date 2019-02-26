package storage

import (
	"sync"

	"github.com/keybase/client/go/chat/globals"
	"github.com/keybase/client/go/chat/utils"
)

type locksRepo struct {
	Inbox, Outbox, Version, ConvFailures sync.Mutex
	StorageLockTab                       *utils.ConversationLockTab
}

var initLocksOnce sync.Once
var locks = &locksRepo{}

func (l *locksRepo) initOnce(g *globals.Context) {
	initLocksOnce.Do(func() {
		l.StorageLockTab = utils.NewConversationLockTab(g)
	})
}
