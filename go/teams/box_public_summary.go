package teams

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/go-codec/codec"
)

// TODO do we need a full UV?
type boxPublicSummaryTable map[keybase1.UID]keybase1.Seqno

type boxPublicSummary struct {
	table   boxPublicSummaryTable
	encoded []byte
}

func newBoxPublicSummary(d map[keybase1.UserVersion]keybase1.PerUserKey) (*boxPublicSummary, error) {
	table := make(boxPublicSummaryTable, len(d))
	for uv, puk := range d {
		q, found := table[uv.Uid]
		if !found || q < puk.Seqno {
			table[uv.Uid] = puk.Seqno
		}
	}
	return newBoxPublicSummaryFromTable(table)
}

func newBoxPublicSummaryFromTable(table boxPublicSummaryTable) (*boxPublicSummary, error) {
	ret := boxPublicSummary{
		table: table,
	}
	err := ret.encode()
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (b *boxPublicSummary) encode() error {
	var mh codec.MsgpackHandle
	mh.WriteExt = true
	mh.Canonical = true
	err := codec.NewEncoderBytes(&b.encoded, &mh).Encode(b.table)
	return err
}

func (b boxPublicSummary) Hash() []byte {
	ret := sha256.Sum256(b.encoded)
	return ret[:]
}

func (b boxPublicSummary) HashHexEncoded() string {
	tmp := b.Hash()
	return hex.EncodeToString(tmp)
}

func (b boxPublicSummary) EncodeToString() string {
	return base64.StdEncoding.EncodeToString(b.encoded)
}

func (b boxPublicSummary) IsEmpty() bool {
	return len(b.table) == 0
}

func (b boxPublicSummary) Export() *keybase1.BoxPublicSummary {
	return &keybase1.BoxPublicSummary{
		Table: b.table,
	}
}
