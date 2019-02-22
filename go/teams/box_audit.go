package teams

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/go-codec/codec"
	"golang.org/x/net/context"

	"github.com/keybase/client/go/protocol/keybase1"
)

// TeamIDKeys takes a set of DBKeys that must all be tid:-style DBKeys and
// extracts the team id from them. Because teams can be loaded via both FTL and
// the slow team loader, we need to use a set so we don't return duplicates.
func KeySetToTeamIDs(dbKeySet libkb.DBKeySet) ([]keybase1.TeamID, error) {
	teamIDSet := make(map[keybase1.TeamID]bool)
	teamIDs := make([]keybase1.TeamID, 0, len(dbKeySet))
	for dbKey, _ := range dbKeySet {
		teamID, err := ParseTeamIDKey(dbKey.Key)
		if err != nil {
			return nil, nil
		}
		_, ok := teamIDSet[teamID]
		if !ok {
			teamIDs = append(teamIDs, teamID)
			teamIDSet[teamID] = true
		}
	}
	return teamIDs, nil
}

func wrap(x byte) []byte {
	return []byte{x}
}

func RandomKnownTeamID(mctx libkb.MetaContext) (teamID keybase1.TeamID, err error) {
	db := mctx.G().LocalDb
	if db == nil {
		return "", fmt.Errorf("nil db")
	}
	dbKeySet, err := db.KeysWithPrefixes(wrap(libkb.DBSlowTeamsAlias), wrap(libkb.DBFTLStorage))
	if err != nil {
		return "", err
	}
	teamIDs, err := KeySetToTeamIDs(dbKeySet)
	if err != nil {
		return "", err
	}
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(teamIDs))))
	if err != nil {
		return "", err
	}
	return teamIDs[idx.Int64()], nil
}

// TODO FEATUREFLAG ME?

type BoxAuditVersion = int

const CurrentBoxAuditVersion BoxAuditVersion = 1

type BoxAuditor struct {
	n int
}

func NewBoxAuditor(g *libkb.GlobalContext) *BoxAuditor {
	ret := &BoxAuditor{n: 5}
	return ret
}

func NewBoxAuditorAndInstall(g *libkb.GlobalContext) {
	g.Log.Warning("@@@NewBoxAuditorAndInstall")
	g.SetTeamBoxAuditor(NewBoxAuditor(g))
	// if g.GetEnv().GetDisableTeamBoxAuditor() {
	// 	g.Log.CDebugf(context.TODO(), "Using dummy auditor, audit disabled")
	// 	g.SetTeamBoxAuditor(dummyBoxAuditor{})
	// } else {
	// }
}

type BoxAuditStatus int

const (
	OKVerified BoxAuditStatus = iota
	OKNotAttempted
	FailureWillRotate
	FailureRetryable
	FailureMaliciousServer
	FailureRetryAttemptsExhausted
)

func (s BoxAuditStatus) IsOK() bool {
	return s == OKVerified || s == OKNotAttempted
}

func (s BoxAuditStatus) IsFatal() bool {
	// should use enum... could forget to add
	return s == FailureMaliciousServer || s == FailureRetryAttemptsExhausted
}

func (s BoxAuditStatus) IsRetryable() bool {
	return !s.IsOK() && !s.IsFatal()
}

type BoxAuditID = []byte

const BoxAuditIDLen = 16

func NewBoxAuditID() (BoxAuditID, error) {
	idBytes := make([]byte, BoxAuditIDLen)
	_, err := rand.Read(idBytes)
	if err != nil {
		return nil, err
	}
	return BoxAuditID(idBytes), nil
}

type BoxAuditLog struct {
	Audits []BoxAudit // last entry is latest

	// TeamIDs who have hit a fatal audit failure or
	// the max number of retryable audit failures.
	// Will not be reaudited unless FTL/slow team loader.
	Blacklist []keybase1.TeamID

	Version BoxAuditVersion
}

func NewBoxAuditLog() *BoxAuditLog {
	return &BoxAuditLog{
		Audits:    nil,
		Blacklist: nil,
		Version:   CurrentBoxAuditVersion,
	}
}

func (l *BoxAuditLog) Last() *BoxAudit {
	if len(l.Audits) == 0 {
		return nil
	}
	return &l.Audits[len(l.Audits)-1]
}

// One sequence of attempts.
type BoxAudit struct {
	ID         BoxAuditID
	InProgress bool
	Attempts   []BoxAuditAttempt
}

const BoxAuditorTag = "SUMAUD"
const BoxAuditQueueDBKey = "queue"

type BoxAuditQueueItem struct {
	Ctime      time.Time
	TeamID     keybase1.TeamID
	BoxAuditID BoxAuditID
}

type BoxAuditQueue struct {
	Items []BoxAuditQueueItem
}

// There are no server operations here, so we don't need to be careful about retrying on possibly malicious errors
func (a *BoxAuditor) PopRetryQueue(mctx libkb.MetaContext) (*BoxAuditQueueItem, error) {
	var queue BoxAuditQueue
	found, err := mctx.G().LocalDb.GetInto(&queue, libkb.DbKey{Typ: libkb.DBBoxAuditor, Key: BoxAuditQueueDBKey})
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, nil
	}

	if len(queue.Items) > 0 {
		item, newItems := queue.Items[0], queue.Items[1:]
		queue.Items = newItems
		err := mctx.G().LocalDb.PutObj(libkb.DbKey{Typ: libkb.DBBoxAuditor, Key: BoxAuditQueueDBKey}, nil, queue)
		if err != nil {
			return nil, err
		}
		return &item, nil
	}

	return nil, nil
}

// There are no server operations here, so we don't need to be careful about retrying on possibly malicious errors
// TODO do we need to filter for duplicates?
// Maybe this has some function name suffix indicating errors are not server driven
func (a *BoxAuditor) PushRetryQueue(mctx libkb.MetaContext, teamID keybase1.TeamID, auditID BoxAuditID) error {
	var queue BoxAuditQueue
	found, err := mctx.G().LocalDb.GetInto(&queue, libkb.DbKey{Typ: libkb.DBBoxAuditor, Key: BoxAuditQueueDBKey})
	if err != nil {
		return err
	}
	if !found {
		queue = BoxAuditQueue{}
	}
	newItems := append(queue.Items, BoxAuditQueueItem{Ctime: time.Now(), TeamID: teamID, BoxAuditID: auditID})
	queue.Items = newItems
	err = mctx.G().LocalDb.PutObj(libkb.DbKey{Typ: libkb.DBBoxAuditor, Key: BoxAuditQueueDBKey}, nil, queue)
	if err != nil {
		return err
	}
	return nil
}

type NonfatalBoxAuditError struct {
	inner error
}

func (e NonfatalBoxAuditError) Error() string {
	return fmt.Sprintf("This audit failed, but will be retried later: %s.", e.inner)
}

type FatalBoxAuditError struct {
	inner error
}

func (e FatalBoxAuditError) Error() string {
	return fmt.Sprintf("This audit failed fatally: %s", e.inner)
}

const MaxRetryAttempts = 6

// Performs one attempt of a BoxAudit. If one is in progress for the teamid,
// make a new attempt. If exceeded max tries, return error.
// Otherwise, make a new audit and fill it with one attempt. Return an error if it's fatal only.
func (a *BoxAuditor) BoxAuditTeam(mctx libkb.MetaContext, teamID keybase1.TeamID) error {
	mctx = mctx.WithLogTag(BoxAuditorTag)

	// Should lock this teamid somehow
	log, err := a.GetLogFromDisk(mctx, teamID)
	if err != nil {
		return NonfatalBoxAuditError{err}
	}

	if log == nil {
		log = NewBoxAuditLog()
	}

	lastAudit := log.Last()
	isRetry := lastAudit != nil && lastAudit.InProgress

	attempt := a.Attempt(mctx, teamID, isRetry)

	var id BoxAuditID
	if isRetry {
		// If there's already an inprogress Audit (i.e., previous failure and
		// we're doing a retry), rotate and do a new attempt in the same audit
		id = lastAudit.ID
		newAudit := BoxAudit{
			ID:         lastAudit.ID,
			InProgress: attempt.Status.IsRetryable(),
			Attempts:   append(lastAudit.Attempts, attempt),
		}
		log.Audits[len(log.Audits)-1] = newAudit
	} else {
		// If the last audit was completed, start a new audit.
		id, err = NewBoxAuditID()
		if err != nil {
			return NonfatalBoxAuditError{err}
		}

		audit := BoxAudit{
			ID:         id,
			InProgress: attempt.Status.IsRetryable(),
			Attempts:   []BoxAuditAttempt{attempt},
		}

		log.Audits = append((*log).Audits, audit)
	}

	err = a.PutLogToDisk(mctx, teamID, log)
	if err != nil {
		return NonfatalBoxAuditError{err}
	}

	if !attempt.Status.IsOK() {
		if attempt.Status.IsFatal() {
			return FatalBoxAuditError{attempt.Error}
		} else {
			if len(log.Last().Attempts) >= MaxRetryAttempts {
				return FatalBoxAuditError{attempt.Error}
			}
			err := a.PushRetryQueue(mctx, teamID, id)
			if err != nil {
				return NonfatalBoxAuditError{err}
			}
			return NonfatalBoxAuditError{attempt.Error}
		}
	}

	return nil
}

func (a *BoxAuditor) GetLogFromDisk(mctx libkb.MetaContext, teamID keybase1.TeamID) (*BoxAuditLog, error) {
	var log BoxAuditLog
	found, err := mctx.G().LocalDb.GetInto(&log, libkb.DbKey{Typ: libkb.DBBoxAuditor, Key: string(teamID)})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	if log.Version != CurrentBoxAuditVersion {
		mctx.CDebugf("Discarding audit at version %d (we are supporting %d)", log.Version, CurrentBoxAuditVersion)
		return nil, nil
	}
	return &log, nil
}

func (a *BoxAuditor) PutLogToDisk(mctx libkb.MetaContext, teamID keybase1.TeamID, log *BoxAuditLog) error {
	return mctx.G().LocalDb.PutObj(libkb.DbKey{Typ: libkb.DBBoxAuditor, Key: string(teamID)}, nil, log)
}

type BoxAuditAttempt struct {
	Time            time.Time
	Status          BoxAuditStatus
	Error           error
	Generation      *keybase1.PerTeamKeyGeneration
	ExpectedSummary *boxPublicSummary

	// only non-nil if different iff result is bad?
	ActualSummary *boxPublicSummary
}

func (a *BoxAuditor) Attempt(mctx libkb.MetaContext, teamID keybase1.TeamID, isRetry bool) BoxAuditAttempt {
	attempt := BoxAuditAttempt{
		Time: time.Now(),
	}
	defer func() {
		// TODO RM
		spew.Dump(attempt)
	}()

	// what if its open/public team?
	team, err := Load(context.TODO(), mctx.G(), keybase1.LoadTeamArg{
		ID:          teamID,
		ForceRepoll: true,
		// TODO other opts?0
	})
	if err != nil {
		attempt.Status = FailureRetryable
		attempt.Error = err
		return attempt
	}
	if team == nil {
		attempt.Status = FailureRetryable
		attempt.Error = fmt.Errorf("got nil team")
		return attempt
	}

	if isRetry {
		err := team.Rotate(mctx.Ctx())
		if err != nil {
			attempt.Status = FailureRetryable
			attempt.Error = fmt.Errorf("failed to rotate team before retrying audit: %s", err)
			return attempt
		}
	}

	g := team.Generation()
	attempt.Generation = &g

	// TODO SHOULDNT audit if Open
	shouldAudit, err := a.ShouldAudit(mctx, *team)
	if err != nil {
		attempt.Status = FailureRetryable
		attempt.Error = err
		return attempt
	}
	if !shouldAudit {
		attempt.Status = OKNotAttempted
		return attempt
	}

	expectedSummary, err := calculateExpectedSummary(mctx, team)
	if err != nil {
		attempt.Status = FailureRetryable
		attempt.Error = err
		return attempt
	}
	attempt.ExpectedSummary = &expectedSummary
	fmt.Println()
	fmt.Printf("%+v\n", expectedSummary)

	actualSummary, err := retrieveAndVerifySigchainSummary(mctx, team)
	if err != nil {
		attempt.Status = FailureRetryable
		attempt.Error = err
		return attempt
	}
	fmt.Printf("%+v\n", actualSummary)

	if !bytes.Equal(expectedSummary.Hash(), actualSummary.Hash()) {
		attempt.Status = FailureRetryable
		attempt.ActualSummary = &actualSummary
		attempt.Error = fmt.Errorf("box summary hash mismatch")
		return attempt
	}

	attempt.Status = OKVerified
	return attempt
}

func (a *BoxAuditor) ShouldAudit(mctx libkb.MetaContext, team Team) (bool, error) {
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
		"id":         libkb.S{Val: team.ID.String()},
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

func (a *BoxAuditor) OnLogout(mctx libkb.MetaContext) {
	return
}
