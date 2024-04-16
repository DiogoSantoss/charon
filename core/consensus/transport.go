// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"context"
	"reflect"
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

	recvBufferCoin chan commoncoin.CommonCoinMessage[core.Duty] // Common coin inner receive buffer.
	recvBufferABA  chan aba.ABAMessage[core.Duty]               // ABA inner receive buffer.
	recvBufferVCBC chan vcbc.VCBCMessage[core.Duty, [32]byte]   // VCBC inner receive buffer.

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

func (t *transport) BroadcastCoin(ctx context.Context, msg commoncoin.CommonCoinMessage[core.Duty]) error {

	// Send to self (async since buffer is blocking).
	go func() {
		select {
		case <-ctx.Done():
		case t.recvBufferCoin <- msg:
			// TODO sniff
		}
	}()

	for _, p := range t.component.peers {
		if p.ID == t.component.tcpNode.ID() {
			// Do not broadcast to self
			continue
		}

		err := t.component.sender.SendAsync(ctx, t.component.tcpNode, "/charon/consensus/aleabft/commoncoin/0.1.0", p.ID, &pbv1.CommonCoinMsg{
			Source:         msg.Source,
			Duty:           core.DutyToProto(msg.Instance),
			AgreementRound: msg.AgreementRound,
			AbaRound:       msg.AbaRound,
			Sig:            msg.Sig[:],
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *transport) BroadcastABA(ctx context.Context, msg aba.ABAMessage[core.Duty]) error {

	// Send to self (async since buffer is blocking).
	go func() {
		select {
		case <-ctx.Done():
		case t.recvBufferABA <- msg:
			// TODO sniff
		}
	}()

	for _, p := range t.component.peers {
		if p.ID == t.component.tcpNode.ID() {
			// Do not broadcast to self
			continue
		}

		v := make([]int32, 0)
		for b := range msg.Values {
			v = append(v, int32(b))
		}

		err := t.component.sender.SendAsync(ctx, t.component.tcpNode, "/charon/consensus/aleabft/aba/0.1.0", p.ID, &pbv1.ABAMsg{
			Type:           int64(msg.MsgType),
			Source:         msg.Source,
			Duty:           core.DutyToProto(msg.Instance),
			AgreementRound: msg.AgreementRound,
			Round:          msg.Round,
			Estimative:     int32(msg.Estimative),
			Values:         v,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *transport) BroadcastVCBC(ctx context.Context, msg vcbc.VCBCMessage[core.Duty, [32]byte]) error {

	// Send to self (async since buffer is blocking).
	go func() {
		select {
		case <-ctx.Done():
		case t.recvBufferVCBC <- msg:
			// TODO sniff
		}
	}()

	for _, p := range t.component.peers {
		if p.ID == t.component.tcpNode.ID() {
			// Do not broadcast to self
			continue
		}

		var content *pbv1.VCBCMsgContent

		if !reflect.ValueOf(msg.Content).IsZero() {
			content = &pbv1.VCBCMsgContent{
				Type:      int64(msg.Content.MsgType),
				Tag:       msg.Content.Tag,
				ValueHash: msg.Content.ValueHash,
			}
		}

		err := t.component.sender.SendAsync(ctx, t.component.tcpNode, "/charon/consensus/aleabft/vcbc/0.1.0", p.ID, &pbv1.VCBCMsg{
			Source:       msg.Source,
			Content:      content,
			Duty:         core.DutyToProto(msg.Instance),
			Value:        msg.Value[:],
			PartialSig:   msg.PartialSig[:],
			ThresholdSig: msg.ThresholdSig[:],
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *transport) UnicastVCBC(ctx context.Context, target int64, msg vcbc.VCBCMessage[core.Duty, [32]byte]) error {

	id, _ := t.component.getPeerIdx()
	if id == (target - 1) {
		// Send to self (async since buffer is blocking).
		go func() {
			select {
			case <-ctx.Done():
			case t.recvBufferVCBC <- msg:
				// TODO sniff
			}
		}()
	} else {

		peer := t.component.peers[target-1]

		var content *pbv1.VCBCMsgContent

		if !reflect.ValueOf(msg.Content).IsZero() {
			content = &pbv1.VCBCMsgContent{
				Type:      int64(msg.Content.MsgType),
				Tag:       msg.Content.Tag,
				ValueHash: msg.Content.ValueHash,
			}
		}

		err := t.component.sender.SendAsync(ctx, t.component.tcpNode, "/charon/consensus/aleabft/vcbc/0.1.0", peer.ID, &pbv1.VCBCMsg{
			Source:       msg.Source,
			Content:      content,
			Duty:         core.DutyToProto(msg.Instance),
			Value:        msg.Value[:],
			PartialSig:   msg.PartialSig[:],
			ThresholdSig: msg.ThresholdSig[:],
		})
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

func (t *transport) ProcessReceivesCoin(ctx context.Context, outerBuffer chan *pbv1.CommonCoinMsg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-outerBuffer:
			newCommonCoinMsg := commoncoin.CommonCoinMessage[core.Duty]{
				Source:         msg.Source,
				Instance:       core.DutyFromProto(msg.Duty),
				AgreementRound: msg.AgreementRound,
				AbaRound:       msg.AbaRound,
				Sig:            tbls.Signature(msg.GetSig()),
			}
			t.recvBufferCoin <- newCommonCoinMsg
		}
	}
}

func (t *transport) ProcessReceivesABA(ctx context.Context, outerBuffer chan *pbv1.ABAMsg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-outerBuffer:
			values := make(map[byte]struct{})
			for _, v := range msg.Values {
				values[byte(v)] = struct{}{}
			}
			newABAMsg := aba.ABAMessage[core.Duty]{
				MsgType:        aba.MsgType(msg.GetType()),
				Source:         msg.Source,
				Instance:       core.DutyFromProto(msg.Duty),
				AgreementRound: msg.AgreementRound,
				Round:          msg.Round,
				Estimative:     byte(msg.Estimative),
				Values:         values,
			}

			t.recvBufferABA <- newABAMsg
		}
	}
}

func (t *transport) ProcessReceivesVCBC(ctx context.Context, outerBuffer chan *pbv1.VCBCMsg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-outerBuffer:
			var content vcbc.VCBCMessageContent
			if msg.Content != nil {
				content = vcbc.VCBCMessageContent{
					MsgType:   vcbc.MsgType(msg.Content.GetType()),
					Tag:       msg.Content.GetTag(),
					ValueHash: msg.Content.GetValueHash(),
				}
			}

			newVCBCMsg := vcbc.VCBCMessage[core.Duty, [32]byte]{
				Source:       msg.Source,
				Content:      content,
				Instance:     core.DutyFromProto(msg.Duty),
				Value:        [32]byte(msg.Value),
				PartialSig:   tbls.Signature(msg.PartialSig),
				ThresholdSig: tbls.Signature(msg.ThresholdSig),
			}
			t.recvBufferVCBC <- newVCBCMsg
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
