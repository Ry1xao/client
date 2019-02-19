package teams

import (
	"testing"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/stretchr/testify/require"
)

func TestBoxAudit(t *testing.T) {
	fus, tcs, cleanup := setupNTests(t, 3)
	defer cleanup()

	t.Logf("create team")
	teamName, teamID := createTeam2(*tcs[0])
	m := make([]libkb.MetaContext, 3)
	for i, tc := range tcs {
		m[i] = libkb.NewMetaContextForTest(*tc)
	}

	// We set up codenames for 3 users, A, B and C
	const (
		A = 0
		B = 1
		C = 2
	)

	_ = func(asUser int) {
		_, err := Load(m[asUser].Ctx(), tcs[asUser].G, keybase1.LoadTeamArg{
			Name:    teamName.String(),
			Public:  false,
			StaleOK: true,
		})
		require.NoError(t, err)
	}

	addC := func(asUser int) {
		_, err := AddMember(m[asUser].Ctx(), tcs[asUser].G, teamName.String(), fus[C].Username, keybase1.TeamRole_READER)
		require.NoError(t, err)
	}

	rmC := func(asUser int) {
		err := RemoveMember(m[asUser].Ctx(), tcs[asUser].G, teamName.String(), fus[C].Username)
		require.NoError(t, err)
	}

	t.Logf("A adds B to the team as an admin")
	_, err := AddMember(m[0].Ctx(), tcs[0].G, teamName.String(), fus[1].Username, keybase1.TeamRole_ADMIN)
	require.NoError(t, err)

	addC(A)
	rmC(A)
	// load(B)
	// addC(B)

	auditor := tcs[0].G.GetTeamBoxAuditor()
	err = auditor.BoxAuditTeam(m[0], teamID)
	require.NoError(t, err)
}
