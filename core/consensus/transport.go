// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"context"
	"fmt"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/alea/aba"
	"github.com/obolnetwork/charon/core/alea/commoncoin"
	"github.com/obolnetwork/charon/core/alea/vcbc"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
	"github.com/obolnetwork/charon/tbls"
)

// transport encapsulates receiving and broadcasting for a consensus instance/duty.
type transport struct {
	// Immutable state
	component  *Component
	recvBuffer chan qbft.Msg[core.Duty, [32]byte] // Instance inner receive buffer.
	sniffer    *sniffer

	recvBufferCoin chan commoncoin.CommonCoinMsg[core.Duty] // Common coin inner receive buffer.
	recvBufferABA  chan aba.ABAMsg[core.Duty]               // ABA inner receive buffer.
	recvBufferVCBC chan vcbc.VCBCMsg[core.Duty, [32]byte]   // VCBC2 inner receive buffer.

	// Mutable state
	valueMu sync.Mutex
	valueCh <-chan proto.Message    // Channel providing lazy proposed values.
	values  map[[32]byte]*anypb.Any // maps any-wrapped proposed values to their hashes
}

// setValues caches the values and their hashes.
func (t *transport) setValues(msg msg) {
	t.valueMu.Lock()
	defer t.valueMu.Unlock()

	for k, v := range msg.values {
		t.values[k] = v
	}
}

func (t *transport) setValuesVCBC(value *anypb.Any, hash [32]byte) {
	t.valueMu.Lock()
	defer t.valueMu.Unlock()
	t.values[hash] = value
}

// getValue returns the value by its hash.
func (t *transport) getValue(hash [32]byte) (*anypb.Any, error) {
	t.valueMu.Lock()
	defer t.valueMu.Unlock()

	// First check if we have a new value.
	select {
	case value := <-t.valueCh:
		valueHash, err := hashProto(value)
		if err != nil {
			return nil, err
		}

		anyValue, err := anypb.New(value)
		if err != nil {
			return nil, errors.Wrap(err, "wrap any value")
		}
		t.values[valueHash] = anyValue
	default:
		// No new values
	}

	pb, ok := t.values[hash]
	if !ok {
		fmt.Println(hash)
		return nil, errors.New("unknown value")
	}

	return pb, nil
}

// Broadcast creates a msg and sends it to all peers (including self).
func (t *transport) Broadcast(ctx context.Context, typ qbft.MsgType, duty core.Duty,
	peerIdx int64, round int64, valueHash [32]byte, pr int64, pvHash [32]byte,
	justification []qbft.Msg[core.Duty, [32]byte],
) error {
	// Get all hashes
	var hashes [][32]byte
	hashes = append(hashes, valueHash)
	hashes = append(hashes, pvHash)
	for _, just := range justification {
		msg, ok := just.(msg)
		if !ok {
			return errors.New("invalid justification message")
		}
		hashes = append(hashes, msg.valueHash)
		hashes = append(hashes, msg.preparedValueHash)
	}

	// Get values by their hashes if not zero.
	values := make(map[[32]byte]*anypb.Any)
	for _, hash := range hashes {
		if hash == [32]byte{} || values[hash] != nil {
			continue
		}

		value, err := t.getValue(hash)
		if err != nil {
			return err
		}

		values[hash] = value
	}

	// Make the message
	msg, err := createMsg(typ, duty, peerIdx, round, valueHash, pr,
		pvHash, values, justification, t.component.privkey)
	if err != nil {
		return err
	}

	// Send to self (async since buffer is blocking).
	go func() {
		select {
		case <-ctx.Done():
		case t.recvBuffer <- msg:
			t.sniffer.Add(msg.ToConsensusMsg())
		}
	}()

	for _, p := range t.component.peers {
		if p.ID == t.component.tcpNode.ID() {
			// Do not broadcast to self
			continue
		}

		err = t.component.sender.SendAsync(ctx, t.component.tcpNode, protocolID2, p.ID, msg.ToConsensusMsg())
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *transport) BroadcastCoin(ctx context.Context, source int64, instance core.Duty, agreementRound, abaRound int64, sig tbls.Signature) error {

	msg := &pbv1.CommonCoinMsg{
		Source:         source,
		Duty:           core.DutyToProto(instance),
		AgreementRound: agreementRound,
		AbaRound:       abaRound,
		Sig:            sig[:],
	}

	commonCoinMsg := commonCoinMsg{
		msg: msg,
	}

	// Send to self (async since buffer is blocking).
	go func() {
		select {
		case <-ctx.Done():
		case t.recvBufferCoin <- commonCoinMsg:
			// TODO sniff
		}
	}()

	for _, p := range t.component.peers {
		if p.ID == t.component.tcpNode.ID() {
			// Do not broadcast to self
			continue
		}

		err := t.component.sender.SendAsync(ctx, t.component.tcpNode, "/charon/consensus/aleabft/commoncoin/0.1.0", p.ID, msg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *transport) BroadcastABA(ctx context.Context, source int64, msgType aba.MsgType,
	duty core.Duty, agreementRound, round int64, estimative byte,
	values map[byte]struct{}) error {

	v := make([]int32, 0)
	for b := range values {
		v = append(v, int32(b))
	}

	msg := &pbv1.ABAMsg{
		Type:           int64(msgType),
		Source:         source,
		Duty:           core.DutyToProto(duty),
		AgreementRound: agreementRound,
		Round:          round,
		Estimative:     int32(estimative),
		Values:         v,
	}

	abaMsg := abaMsg{
		msg: msg,
	}

	// Send to self (async since buffer is blocking).
	go func() {
		select {
		case <-ctx.Done():
		case t.recvBufferABA <- abaMsg:
			// TODO sniff
		}
	}()

	for _, p := range t.component.peers {
		if p.ID == t.component.tcpNode.ID() {
			// Do not broadcast to self
			continue
		}

		err := t.component.sender.SendAsync(ctx, t.component.tcpNode, "/charon/consensus/aleabft/aba/0.1.0", p.ID, msg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *transport) BroadcastVCBC(
	ctx context.Context,
	source int64, msgType vcbc.MsgType, tag string, valueHash []byte,
	duty core.Duty, value [32]byte,
	partialSig tbls.Signature, thresholdSig tbls.Signature, sigs map[int64][]byte,
) error {

	var realValue *anypb.Any
	if msgType == vcbc.MsgFinal {
		value, err := t.getValue(value)
		if err != nil {
			return err
		}
		realValue = value
	}

	content := &pbv1.VCBCMsgContent{
		Type:      int64(msgType),
		Tag:       tag,
		ValueHash: valueHash,
	}

	msg := &pbv1.VCBCMsg{
		Source:       source,
		Content:      content,
		Duty:         core.DutyToProto(duty),
		Value:        value[:],
		PartialSig:   partialSig[:],
		ThresholdSig: thresholdSig[:],
		RealValue:    realValue,
		Sigs:         sigs,
	}

	vcbcMsg := vcbcMsg{
		msg: msg,
	}

	// Send to self (async since buffer is blocking).
	go func() {
		select {
		case <-ctx.Done():
		case t.recvBufferVCBC <- vcbcMsg:
			// TODO sniff
		}
	}()

	for _, p := range t.component.peers {
		if p.ID == t.component.tcpNode.ID() {
			// Do not broadcast to self
			continue
		}

		err := t.component.sender.SendAsync(ctx, t.component.tcpNode, "/charon/consensus/aleabft/vcbc/0.1.0", p.ID, msg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *transport) UnicastVCBC(
	ctx context.Context, target int64,
	source int64, msgType vcbc.MsgType, tag string, valueHash []byte,
	duty core.Duty, value [32]byte,
	partialSig tbls.Signature, thresholdSig tbls.Signature, sigs map[int64][]byte,
) error {

	var realValue *anypb.Any
	if msgType == vcbc.MsgAnswer {
		value, err := t.getValue(value)
		if err != nil {
			return err
		}
		realValue = value
	}

	id, _ := t.component.getPeerIdx()

	content := &pbv1.VCBCMsgContent{
		Type:      int64(msgType),
		Tag:       tag,
		ValueHash: valueHash,
	}

	msg := &pbv1.VCBCMsg{
		Source:       source,
		Content:      content,
		Duty:         core.DutyToProto(duty),
		Value:        value[:],
		PartialSig:   partialSig[:],
		ThresholdSig: thresholdSig[:],
		RealValue:    realValue,
		Sigs:         sigs,
	}

	vcbcMsg := vcbcMsg{
		msg: msg,
	}

	if id == (target - 1) {
		// Send to self (async since buffer is blocking).
		go func() {
			select {
			case <-ctx.Done():
			case t.recvBufferVCBC <- vcbcMsg:
				// TODO sniff
			}
		}()
	} else {
		peer := t.component.peers[target-1]

		err := t.component.sender.SendAsync(ctx, t.component.tcpNode, "/charon/consensus/aleabft/vcbc/0.1.0", peer.ID, msg)
		if err != nil {
			return err
		}
	}

	return nil
}

// ProcessReceives processes received messages from the outer buffer until the context is closed.
func (t *transport) ProcessReceives(ctx context.Context, outerBuffer chan msg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-outerBuffer:
			t.setValues(msg)

			select {
			case <-ctx.Done():
				return
			case t.recvBuffer <- msg:
				t.sniffer.Add(msg.ToConsensusMsg())
			}
		}
	}
}

func (t *transport) ProcessReceivesCoin(ctx context.Context, outerBuffer chan commonCoinMsg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-outerBuffer:

			// TODO Why another select
			select {
			case <-ctx.Done():
				return
			case t.recvBufferCoin <- msg:
			}

		}
	}
}

func (t *transport) ProcessReceivesABA(ctx context.Context, outerBuffer chan abaMsg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-outerBuffer:
			// TODO Why another select
			select {
			case <-ctx.Done():
				return
			case t.recvBufferABA <- msg:
			}

		}
	}
}

func (t *transport) ProcessReceivesVCBC(ctx context.Context, outerBuffer chan vcbcMsg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-outerBuffer:
			if msg.MsgType() == vcbc.MsgFinal || msg.MsgType() == vcbc.MsgAnswer {
				t.setValuesVCBC(msg.RealValue(), msg.Value())
			}
			select {
			case <-ctx.Done():
				return
			case t.recvBufferVCBC <- msg:
			}
		}
	}
}

// createMsg returns a new message by converting the inputs into a protobuf
// and wrapping that in a msg type.
func createMsg(typ qbft.MsgType, duty core.Duty,
	peerIdx int64, round int64, vHash [32]byte, pr int64, pvHash [32]byte,
	values map[[32]byte]*anypb.Any, justification []qbft.Msg[core.Duty, [32]byte],
	privkey *k1.PrivateKey,
) (msg, error) {
	pbMsg := &pbv1.QBFTMsg{
		Type:              int64(typ),
		Duty:              core.DutyToProto(duty),
		PeerIdx:           peerIdx,
		Round:             round,
		ValueHash:         vHash[:],
		PreparedRound:     pr,
		PreparedValueHash: pvHash[:],
	}

	pbMsg, err := signMsg(pbMsg, privkey)
	if err != nil {
		return msg{}, err
	}

	// Transform justifications into protobufs
	var justMsgs []*pbv1.QBFTMsg
	for _, j := range justification {
		impl, ok := j.(msg)
		if !ok {
			return msg{}, errors.New("invalid justification")
		}
		justMsgs = append(justMsgs, impl.msg) // Note nested justifications are ignored.
	}

	return newMsg(pbMsg, justMsgs, values)
}

// newSniffer returns a new sniffer.
func newSniffer(nodes, peerIdx int64) *sniffer {
	return &sniffer{
		nodes:     nodes,
		peerIdx:   peerIdx,
		startedAt: time.Now(),
	}
}

// sniffer buffers consensus messages.
type sniffer struct {
	nodes     int64
	peerIdx   int64
	startedAt time.Time

	mu   sync.Mutex
	msgs []*pbv1.SniffedConsensusMsg
}

// Add adds a message to the sniffer buffer.
func (c *sniffer) Add(msg *pbv1.ConsensusMsg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgs = append(c.msgs, &pbv1.SniffedConsensusMsg{
		Timestamp: timestamppb.Now(),
		Msg:       msg,
	})
}

// Instance returns the buffered messages as an instance.
func (c *sniffer) Instance() *pbv1.SniffedConsensusInstance {
	c.mu.Lock()
	defer c.mu.Unlock()

	return &pbv1.SniffedConsensusInstance{
		Nodes:     c.nodes,
		PeerIdx:   c.peerIdx,
		StartedAt: timestamppb.New(c.startedAt),
		Msgs:      c.msgs,
	}
}
