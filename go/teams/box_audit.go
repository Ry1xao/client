package teams

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
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
			return nil, err
		}
		_, ok := teamIDSet[teamID]
		if !ok {
			teamIDs = append(teamIDs, teamID)
			teamIDSet[teamID] = true
		}
	}
	return teamIDs, nil
}

// filter out ones in jail?
// also impteams might dominate. Don't want that.
// might just need a separate pool...
func KnownTeamIDs(mctx libkb.MetaContext) ([]keybase1.TeamID, error) {
	db := mctx.G().LocalDb
	if db == nil {
		return nil, fmt.Errorf("nil db")
	}
	dbKeySet, err := db.KeysWithPrefixes(libkb.LevelDbPrefix(libkb.DBSlowTeamsAlias), libkb.LevelDbPrefix(libkb.DBFTLStorage))
	if err != nil {
		return nil, err
	}
	teamIDs, err := KeySetToTeamIDs(dbKeySet)
	if err != nil {
		return nil, err
	}
	return teamIDs, nil
}

func RandomKnownTeamID(mctx libkb.MetaContext) (teamID *keybase1.TeamID, err error) {
	knownTeamIDs, err := KnownTeamIDs(mctx)
	if err != nil {
		return nil, err
	}
	N := len(knownTeamIDs)
	if N == 0 {
		return nil, nil
	}
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(N))) // [0, n)
	if err != nil {
		return nil, err
	}
	return &knownTeamIDs[idx.Int64()], nil
}

const CurrentBoxAuditVersion Version = 2

type BoxAuditor struct {
	sync.Mutex
	Initialized bool
	Version     Version
}

func (a *BoxAuditor) OnLogout(mctx libkb.MetaContext) {
	return
}

func NewBoxAuditor(g *libkb.GlobalContext) *BoxAuditor {
	return &BoxAuditor{Initialized: true, Version: CurrentBoxAuditVersion}
}

func NewBoxAuditorAndInstall(g *libkb.GlobalContext) {
	if g.GetEnv().GetDisableTeamBoxAuditor() {
		g.Log.CDebugf(context.TODO(), "Box auditor disabled: not configuring auditor")
	} else {
		g.SetTeamBoxAuditor(NewBoxAuditor(g))
	}
}

// BoxAuditLog is a log of audits for a particular team.
type BoxAuditLog struct {
	// The last entry of Audits is the latest one.
	Audits []BoxAudit

	// Whether the last Audit is still in progress, false if there are no
	// Audits.
	InProgress bool

	Version Version
}

func (l BoxAuditLog) GetVersion() Version {
	return l.Version
}

func BoxAuditLogDbKey(teamID keybase1.TeamID) libkb.DbKey {
	return libkb.DbKey{Typ: libkb.DBBoxAuditor, Key: string(teamID)}
}

func NewBoxAuditLog(version Version) *BoxAuditLog {
	return &BoxAuditLog{
		Audits:     nil,
		InProgress: false,
		Version:    version,
	}
}

func (l *BoxAuditLog) Last() *BoxAudit {
	if l == nil || len(l.Audits) == 0 {
		return nil
	}
	return &l.Audits[len(l.Audits)-1]
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

// A BoxAudit is a single sequence of audit attempts for a single team.
type BoxAudit struct {
	ID       BoxAuditID
	Attempts []keybase1.BoxAuditAttempt
}

func BoxAuditQueueDbKey() libkb.DbKey {
	return libkb.DbKey{Typ: libkb.DBBoxAuditorPermanent, Key: "queue"}
}

type BoxAuditQueueItem struct {
	Ctime      time.Time
	TeamID     keybase1.TeamID
	BoxAuditID BoxAuditID
}

type BoxAuditQueue struct {
	Items   []BoxAuditQueueItem
	Version Version
}

func (q *BoxAuditQueue) GetVersion() Version {
	return q.Version
}

func NewBoxAuditQueue(version Version) *BoxAuditQueue {
	return &BoxAuditQueue{
		Items:   nil,
		Version: version,
	}
}

// BoxAuditJail contains TeamIDs that have hit a fatal audit failure or the max
// number of retryable audit failures. Teams in jail will not be reaudited
// unless they are explicitly loaded by the fast or slow team loaders.
type BoxAuditJail struct {
	TeamIDs map[keybase1.TeamID]bool
	Version Version
}

func (j *BoxAuditJail) GetVersion() Version {
	return j.Version
}

func BoxAuditJailDbKey() libkb.DbKey {
	return libkb.DbKey{Typ: libkb.DBBoxAuditorPermanent, Key: "jail"}
}

func NewBoxAuditJail(version Version) *BoxAuditJail {
	return &BoxAuditJail{
		TeamIDs: make(map[keybase1.TeamID]bool),
		Version: version,
	}
}

type Version int
type Versioned interface {
	GetVersion() Version
}

func maybeGetVersionedFromDisk(mctx libkb.MetaContext, dbKey libkb.DbKey, i Versioned, currentVersion Version) (found bool, err error) {
	found, err = mctx.G().LocalDb.GetInto(&i, dbKey)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	v, ok := (i).(Versioned)
	if !ok {
		return false, fmt.Errorf("failed to cast %+v as a Versioned", i)
	}
	if v.GetVersion() != currentVersion {
		mctx.CDebugf("Not returning outdated obj at version %d (now at version %d)", v.GetVersion(), currentVersion)
		// We do not delete the old data.
		return false, nil
	}
	return true, nil
}

func putToDisk(mctx libkb.MetaContext, dbKey libkb.DbKey, i interface{}) error {
	return mctx.G().LocalDb.PutObj(dbKey, nil, i)
}

func (a *BoxAuditor) clearRetryQueueOf(mctx libkb.MetaContext, teamID keybase1.TeamID) error {
	var queue BoxAuditQueue
	found, err := maybeGetVersionedFromDisk(mctx, BoxAuditQueueDbKey(), &queue, a.Version)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	newItems := make([]BoxAuditQueueItem, 0, len(queue.Items))
	for _, item := range queue.Items {
		if item.TeamID != teamID {
			newItems = append(newItems, item)
		}
	}
	queue.Items = newItems
	err = putToDisk(mctx, BoxAuditQueueDbKey(), queue)
	if err != nil {
		return err
	}
	return nil
}

func (a *BoxAuditor) popRetryQueue(mctx libkb.MetaContext) (*BoxAuditQueueItem, error) {
	var queue BoxAuditQueue
	found, err := maybeGetVersionedFromDisk(mctx, BoxAuditQueueDbKey(), &queue, a.Version)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	if len(queue.Items) > 0 {
		item, newItems := queue.Items[0], queue.Items[1:]
		queue.Items = newItems
		err := putToDisk(mctx, BoxAuditQueueDbKey(), queue)
		if err != nil {
			return nil, err
		}
		return &item, nil
	}
	return nil, nil
}

const MaxBoxAuditQueueSize = 100

func (a *BoxAuditor) pushRetryQueue(mctx libkb.MetaContext, teamID keybase1.TeamID, auditID BoxAuditID) error {
	var queue *BoxAuditQueue
	found, err := maybeGetVersionedFromDisk(mctx, BoxAuditQueueDbKey(), queue, a.Version)
	if err != nil {
		return err
	}
	if found {
		// if already in the queue, remove it so we can bump it to the top
		err = a.clearRetryQueueOf(mctx, teamID)
		if err != nil {
			return err
		}
	} else {
		queue = NewBoxAuditQueue(a.Version)
	}

	queue.Items = append(queue.Items, BoxAuditQueueItem{Ctime: time.Now(), TeamID: teamID, BoxAuditID: auditID})
	if len(queue.Items) > MaxBoxAuditQueueSize {
		// truncate oldest first
		queue.Items = queue.Items[len(queue.Items)-MaxBoxAuditQueueSize:]
	}
	err = putToDisk(mctx, BoxAuditQueueDbKey(), queue)
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
	return fmt.Sprintf("This audit failed fatally. It will not be retried: %s", e.inner)
}

const MaxRetryAttempts = 6

// Performs one attempt of a BoxAudit. If one is in progress for the teamid,
// make a new attempt. If exceeded max tries or hit a malicious error, return a fatal error.
// Otherwise, make a new audit and fill it with one attempt. Return an error if it's fatal only.
// If the attempt failed nonfatally, enqueue it in the retry queue. If it failed fatally,
// add it to the jail.
func (a *BoxAuditor) BoxAuditTeam(mctx libkb.MetaContext, teamID keybase1.TeamID) error {
	a.Lock()
	// TODO when do we have to unlock db?
	defer a.Unlock()

	mctx = mctx.WithLogTag("SUMAUD")
	dbKey := BoxAuditLogDbKey(teamID)

	var log BoxAuditLog
	found, err := maybeGetVersionedFromDisk(mctx, dbKey, &log, a.Version)
	if err != nil {
		return NonfatalBoxAuditError{err}
	}
	if !found {
		log = *NewBoxAuditLog(a.Version)
	}

	lastAudit := log.Last()
	isRetry := log.InProgress

	rotateBeforeAudit := isRetry
	attempt := a.Attempt(mctx, teamID, rotateBeforeAudit)

	var id BoxAuditID
	if isRetry {
		// If there's already an inprogress Audit (i.e., previous failure and
		// we're doing a retry), rotate and do a new attempt in the same audit
		id = lastAudit.ID
		newAudit := BoxAudit{
			ID:       lastAudit.ID,
			Attempts: append(lastAudit.Attempts, attempt),
		}
		log.Audits[len(log.Audits)-1] = newAudit
	} else {
		// If the last audit was completed, start a new audit.
		id, err = NewBoxAuditID()
		if err != nil {
			return NonfatalBoxAuditError{err}
		}
		audit := BoxAudit{
			ID:       id,
			Attempts: []keybase1.BoxAuditAttempt{attempt},
		}
		log.Audits = append(log.Audits, audit)
	}
	log.InProgress = attempt.Result == keybase1.BoxAuditAttemptResult_FAILURE_RETRYABLE

	err = putToDisk(mctx, dbKey, log)
	if err != nil {
		return NonfatalBoxAuditError{err}
	}

	if !attempt.Result.IsOK() {
		if attempt.Result == keybase1.BoxAuditAttemptResult_FAILURE_MALICIOUS_SERVER || len(log.Last().Attempts) >= MaxRetryAttempts {
			err = a.jail(mctx, teamID)
			if err != nil {
				return NonfatalBoxAuditError{err}
			}
			return FatalBoxAuditError{errors.New(*attempt.Error)}
		} else {
			err := a.pushRetryQueue(mctx, teamID, id)
			if err != nil {
				return NonfatalBoxAuditError{err}
			}
			return NonfatalBoxAuditError{errors.New(*attempt.Error)}
		}
	}

	err = a.unjail(mctx, teamID)
	if err != nil {
		return NonfatalBoxAuditError{err}
	}
	return nil
}

func (a *BoxAuditor) jail(mctx libkb.MetaContext, teamID keybase1.TeamID) error {
	var jail BoxAuditJail
	found, err := maybeGetVersionedFromDisk(mctx, BoxAuditJailDbKey(), &jail, a.Version)
	if err != nil {
		return err
	}
	if !found {
		jail = *NewBoxAuditJail(a.Version)
	}
	jail.TeamIDs[teamID] = true
	err = putToDisk(mctx, BoxAuditJailDbKey(), jail)
	if err != nil {
		return err
	}
	return nil
}

func (a *BoxAuditor) unjail(mctx libkb.MetaContext, teamID keybase1.TeamID) error {
	var jail BoxAuditJail
	found, err := maybeGetVersionedFromDisk(mctx, BoxAuditJailDbKey(), &jail, a.Version)
	if err != nil {
		return err
	}
	if !found {
		jail = *NewBoxAuditJail(a.Version)
	}
	delete(jail.TeamIDs, teamID)
	err = putToDisk(mctx, BoxAuditJailDbKey(), jail)
	if err != nil {
		return err
	}
	return nil
}

func (a *BoxAuditor) ShouldAudit(mctx libkb.MetaContext, team Team) (bool, error) {
	role, err := team.MemberRole(mctx.Ctx(), mctx.CurrentUserVersion())
	if err != nil {
		return false, err
	}

	return role.IsOrAbove(keybase1.TeamRole_WRITER), nil
}

// Attempt tries one time to box audit a Team ID. It does not store any
// persistent state to disk.
func (a *BoxAuditor) Attempt(mctx libkb.MetaContext, teamID keybase1.TeamID, rotateBeforeAudit bool) keybase1.BoxAuditAttempt {
	attempt := keybase1.BoxAuditAttempt{
		Result: keybase1.BoxAuditAttemptResult_FAILURE_RETRYABLE,
		Ctime:  keybase1.ToUnixTime(time.Now()),
	}
	defer func() {
		// TODO RM
		spew.Dump(attempt)
	}()

	getErrorMessage := func(err error) *string {
		msg := err.Error()
		return &msg
	}

	// SKIP FOR OPEN TEAM!!!
	// what if its open/public team?
	fmt.Println(teamID)
	team, err := Load(context.TODO(), mctx.G(), keybase1.LoadTeamArg{
		ID:          teamID,
		ForceRepoll: true,
		// TODO other opts?0
	})
	if err != nil {
		attempt.Error = getErrorMessage(err)
		return attempt
	}
	if team == nil {
		attempt.Error = getErrorMessage(fmt.Errorf("got nil team"))
		return attempt
	}

	if rotateBeforeAudit {
		err := team.Rotate(mctx.Ctx())
		if err != nil {
			attempt.Error = getErrorMessage(fmt.Errorf("failed to rotate team before retrying audit: %s", err))
			return attempt
		}
	}

	g := team.Generation()
	// TODO put a teamchain seqno instead of generation?
	attempt.Generation = &g

	// TODO SHOULDNT audit if Open
	shouldAudit, err := a.ShouldAudit(mctx, *team)
	if err != nil {
		attempt.Error = getErrorMessage(err)
		return attempt
	}
	if !shouldAudit {
		attempt.Result = keybase1.BoxAuditAttemptResult_OK_NOT_ATTEMPTED
		return attempt
	}

	actualSummary, err := retrieveAndVerifySigchainSummary(mctx, team)
	if err != nil {
		attempt.Error = getErrorMessage(err)
		return attempt
	}
	fmt.Printf("actual: %+v\n", actualSummary.table)

	expectedSummary, err := calculateExpectedSummary(mctx, team)
	if err != nil {
		attempt.Error = getErrorMessage(err)
		return attempt
	}
	fmt.Printf("expected: %+v\n", expectedSummary.table)

	if !bytes.Equal(expectedSummary.Hash(), actualSummary.Hash()) {
		attempt.Error = getErrorMessage(fmt.Errorf("box summary hash mismatch"))
		return attempt
	}

	attempt.Result = keybase1.BoxAuditAttemptResult_OK_VERIFIED
	return attempt
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
				mctx.CWarningf("skipping user %s who has no per-user-key; possibly reset", uv)
				continue
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
