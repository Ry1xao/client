package service

import (
	"github.com/keybase/client/go/libkb"
	keybase1 "github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/go-framed-msgpack-rpc/rpc"

	"golang.org/x/net/context"
)

type AuditHandler struct {
	libkb.Contextified
	*BaseHandler
}

func NewAuditHandler(xp rpc.Transporter, g *libkb.GlobalContext) *AuditHandler {
	handler := &AuditHandler{
		Contextified: libkb.NewContextified(g),
		BaseHandler:  NewBaseHandler(g, xp),
	}
	return handler
}

var _ keybase1.AuditInterface = (*AuditHandler)(nil)

func (h *AuditHandler) AttemptBoxAudit(ctx context.Context, arg keybase1.AttemptBoxAuditArg) (res keybase1.BoxAuditAttempt, err error) {
	mctx := libkb.NewMetaContext(ctx, h.G())
	defer mctx.CTraceTimed("AuditHandler#AttemptBoxAudit", func() error { return err })()

	attempt := h.G().GetTeamBoxAuditor().Attempt(mctx, arg.TeamID, arg.RotateBeforeAudit)
	return keybase1.BoxAuditAttempt{
		Time:            attempt.Time,
		Status:          attempt.Status,
		Error:           attempt.Error,
		Generation:      attempt.Generation,
		ExpectedSummary: attempt.ExpectedSummary,
		ActualSummary:   attempt.ActualSummary,
	}, nil
}
