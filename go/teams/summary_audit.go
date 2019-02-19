package teams

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/net/context"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/go-codec/codec"
)

// TODO FEATUREFLAG ME?

const SummaryAuditVersion = 1

type SummaryAuditor struct {
	// TODO RM
	i int
}

type SummaryAuditStatus int

const (
	OKVerified SummaryAuditStatus = iota
	OKNotAttempted
	FailureWillRotate
	FailureRetryable
	FailureMaliciousServer
	FailureRetryAttemptsExhausted
)

func (s SummaryAuditStatus) OK() bool {
	return s == OKVerified || s == OKNotAttempted
}

func (s SummaryAuditStatus) Fatal() bool {
	// should use enum... could forget
	return s == FailureMaliciousServer || s == FailureRetryAttemptsExhausted
}

type AuditResult struct {
	Status SummaryAuditStatus
}

const SummaryAuditorTag = "SUMAUD"

func (a *SummaryAuditor) Audit(mctx libkb.MetaContext, teamID keybase1.TeamID) (result AuditResult, err error) {
	mctx = mctx.WithLogTag(SummaryAuditorTag)

	// what if its open/public team?
	team, err := Load(context.TODO(), mctx.G(), keybase1.LoadTeamArg{
		ID:          teamID,
		ForceRepoll: true,
		// TODO other opts?0
	})
	if err != nil {
		return AuditResult{}, err
	}
	if team == nil {
		return AuditResult{}, fmt.Errorf("got nil team")
	}

	shouldAudit, err := a.ShouldAudit(mctx, *team)
	if err != nil {
		return AuditResult{Status: FailureRetryable}, err
	}
	if !shouldAudit {
		return AuditResult{Status: OKNotAttempted}, nil
	}

	expectedSummary, err := calculateExpectedSummary(mctx, team)
	if err != nil {
		return AuditResult{Status: FailureRetryable}, err
	}

	actualSummary, err := retrieveAndVerifySigchainSummary(mctx, team)
	if err != nil {
		return AuditResult{Status: FailureRetryable}, err
	}

	if !bytes.Equal(expectedSummary.Hash(), actualSummary.Hash()) {
		return AuditResult{Status: FailureRetryable}, fmt.Errorf("box summary hash mismatch")
	}

	return AuditResult{Status: OKVerified}, nil
}

func (a *SummaryAuditor) ShouldAudit(mctx libkb.MetaContext, team Team) (bool, error) {
	role, err := team.MemberRole(mctx.Ctx(), mctx.CurrentUserVersion())
	if err != nil {
		return false, err
	}

	return role.IsOrAbove(keybase1.TeamRole_WRITER), nil
}

func calculateExpectedSummary(mctx libkb.MetaContext, team *Team) (boxPublicSummary, error) {
	members, err := team.Members()
	if err != nil {
		return boxPublicSummary{}, err
	}

	d := make(map[keybase1.UserVersion]keybase1.PerUserKey)
	add := func(uvs []keybase1.UserVersion) error {
		for _, uv := range uvs {
			upak, err := loadUPAK2(context.TODO(), mctx.G(), uv.Uid, true) // TODO need force poll?
			if err != nil {
				return err
			}
			puk := upak.Current.GetLatestPerUserKey()
			if puk == nil {
				return fmt.Errorf("user has no puk")
			}
			d[uv] = *puk
		}
		return nil
	}

	err = add(members.Owners)
	if err != nil {
		return boxPublicSummary{}, err
	}
	err = add(members.Admins)
	if err != nil {
		return boxPublicSummary{}, err
	}
	err = add(members.Writers)
	if err != nil {
		return boxPublicSummary{}, err
	}
	err = add(members.Readers)
	if err != nil {
		return boxPublicSummary{}, err
	}

	summary, err := newBoxPublicSummary(d)
	if err != nil {
		return boxPublicSummary{}, err
	}

	return *summary, nil
}

type summaryAuditBatch struct {
	BatchID   int          `json:"batch_id"`
	Hash      string       `json:"hash"`
	NonceTop  string       `json:"nonce_top"`
	SenderKID keybase1.KID `json:"sender_kid"`
	Summary   string       `json:"summary"`
}

type summaryAuditResponse struct {
	Batches []summaryAuditBatch `json:"batches"`
	Status  libkb.AppStatus     `json:"status"`
}

func (r *summaryAuditResponse) GetAppStatus() *libkb.AppStatus {
	return &r.Status
}

// TODO CACHE
// TODO logging
func retrieveAndVerifySigchainSummary(mctx libkb.MetaContext, team *Team) (boxPublicSummary, error) {
	boxSummaryHashes := team.GetBoxSummaryHashes()

	// TODO Doesnt exist on new client...
	g := team.Generation()
	latestHashes := boxSummaryHashes[g]

	a := libkb.NewAPIArg("team/audit")
	a.Args = libkb.HTTPArgs{
		"team_id":    libkb.S{Val: team.ID.String()},
		"generation": libkb.I{Val: int(g)},
	}
	a.NetContext = mctx.Ctx()
	a.SessionType = libkb.APISessionTypeREQUIRED
	var response summaryAuditResponse
	err := mctx.G().API.GetDecode(a, &response)
	if err != nil {
		return boxPublicSummary{}, err
	}

	// Assert server doesn't silently inject additional unchecked batches
	if len(latestHashes) != len(response.Batches) {
		return boxPublicSummary{}, fmt.Errorf("expected %d box summary hashes for generation %d; got %d from server",
			len(latestHashes), g, len(response.Batches))
	}

	table := make(boxPublicSummaryTable)

	for idx, batch := range response.Batches {
		// Expect server to give us back IDs in order (the same order it'll be in the sigchain)
		// TODO completely RM Hash this from the server response
		expectedHash := latestHashes[idx]
		partialTable, err := unmarshalAndVerifyBatch(batch, expectedHash.String())
		if err != nil {
			return boxPublicSummary{}, err
		}

		for uid, seqno := range partialTable {
			// Expect only one uid per batch
			// Removing and readding someone would cause a rotate
			_, ok := table[uid]
			if ok {
				return boxPublicSummary{}, fmt.Errorf("got more than one box for %s in the same generation", uid)
			}

			table[uid] = seqno
		}
	}

	summary, err := newBoxPublicSummaryFromTable(table)
	if err != nil {
		return boxPublicSummary{}, err
	}

	return *summary, nil
}

func unmarshalAndVerifyBatch(batch summaryAuditBatch, expectedHash string) (boxPublicSummaryTable, error) {
	if len(expectedHash) == 0 {
		return nil, fmt.Errorf("expected empty hash")
	}

	msgpacked, err := base64.StdEncoding.DecodeString(batch.Summary)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(msgpacked)
	hexSum := hex.EncodeToString(sum[:])
	// can we compare bytes?
	if expectedHash != hexSum {
		return nil, fmt.Errorf("expected hash %s, got %s from server", expectedHash, hexSum)
	}

	mh := codec.MsgpackHandle{WriteExt: true}
	var table boxPublicSummaryTable
	dec := codec.NewDecoderBytes(msgpacked, &mh)
	err = dec.Decode(&table)
	if err != nil {
		return nil, err
	}

	return table, nil
}
