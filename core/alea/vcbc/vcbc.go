package vcbc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
)

// Verifiable Consistent Broadcast from the paper: "Secure and Efficient Asynchronous Broadcast Protocols"
// Link: https://eprint.iacr.org/2001/006.pdf

type MsgType int

const (
	MsgUnknown MsgType = iota
	MsgSend
	MsgReady
	MsgFinal
	MsgRequest
	MsgAnswer
)

var typeLabels = map[MsgType]string{
	MsgUnknown: "unknown",
	MsgSend:    "send",
	MsgReady:   "ready",
	MsgFinal:   "final",
	MsgRequest: "request",
	MsgAnswer:  "answer",
}

func (t MsgType) Valid() bool {
	return t > MsgUnknown && t < MsgAnswer
}

func (t MsgType) String() string {
	return typeLabels[t]
}

type UponRule int

const (
	UponNothing UponRule = iota
	UponSend
	UponReady
	UponFinal
	UponRequest
	UponAnswer
)

var ruleLabels = map[UponRule]string{
	UponNothing: "nothing",
	UponSend:    "send",
	UponReady:   "ready",
	UponFinal:   "final",
	UponRequest: "request",
	UponAnswer:  "answer",
}

func (r UponRule) String() string {
	return ruleLabels[r]
}

type VCBCResult struct {
	Tag     string
	Message []byte
}

type VCBCMessageContent struct {
	MsgType     MsgType
	Tag         string // Tag is an identifier of type: "ID.<id>.<slot>" where <id> is the sender id and <slot> is a sequence number
	MessageHash []byte
}

type VCBCMessage struct {
	Source       uint
	Content      VCBCMessageContent // Separate struct for content to allow partial signatures on specific content only
	Message      []byte
	PartialSig   tbls.Signature
	ThresholdSig tbls.Signature
}

func classify(slot uint, msg VCBCMessage) UponRule {

	if SlotFromTag(msg.Content.Tag) != slot {
		return UponNothing
	}

	switch msg.Content.MsgType {
	case MsgSend:
		return UponSend
	case MsgReady:
		return UponReady
	case MsgFinal:
		return UponFinal
	case MsgRequest:
		return UponRequest
	case MsgAnswer:
		return UponAnswer
	default:
		panic("bug: invalid message type")
	}
}

type VCBC struct {
	// Immutable values
	N       int
	F       int
	Id      uint
	Slot    uint // PoS slot
	PubKey  tbls.PublicKey
	PubKeys map[uint]tbls.PublicKey
	PrivKey tbls.PrivateKey
	Subs    []func(ctx context.Context, result VCBCResult) error
	// Computed valuee
	ThresholdPartialSigValue int
}

func NewVCBC(n int, f int, id uint, slot uint, pubKey tbls.PublicKey, pubKeys map[uint]tbls.PublicKey, privKey tbls.PrivateKey) *VCBC {
	return &VCBC{
		N:                        n,
		F:                        f,
		Id:                       id,
		Slot:                     slot,
		PubKey:                   pubKey,
		PubKeys:                  pubKeys,
		PrivKey:                  privKey,
		ThresholdPartialSigValue: int(math.Ceil((float64(n) + float64(f) + 1) / 2)),
	}
}

func BuildTag(id uint, slot uint) string {
	return "ID." + strconv.Itoa(int(id)) + "." + strconv.Itoa(int(slot))
}

func SlotFromTag(tag string) uint {
	slot, _ := strconv.Atoi(strings.Split(tag, ".")[2])
	return uint(slot)
}

func IdFromTag(tag string) uint {
	id, _ := strconv.Atoi(strings.Split(tag, ".")[1])
	return uint(id)
}

func (v *VCBC) Subscribe(fn func(ctx context.Context, result VCBCResult) error) {
	v.Subs = append(v.Subs, fn)
}

func (v *VCBC) BroadcastRequest(ctx context.Context, tag string, broadcast func(VCBCMessage) error) error {

	ctx = log.WithTopic(ctx, "vcbc")

	log.Info(ctx, "Broadcasting VCBC request", z.Uint("id", v.Id))

	return broadcast(VCBCMessage{
		Source: v.Id,
		Content: VCBCMessageContent{
			MsgType: MsgRequest,
			Tag:     tag,
		},
	})
}

func (v *VCBC) Run(ctx context.Context, m []byte, broadcast func(VCBCMessage) error, unicast func(uint, VCBCMessage) error, receiveChannel <-chan VCBCMessage) (err error) {

	defer func() {
		// Panics are used for assertions and sanity checks to reduce lines of code
		// and to improve readability. Catch them here.
		if r := recover(); r != nil {
			if !strings.Contains(fmt.Sprint(r), "bug") {
				panic(r) // Only catch internal sanity checks.
			}
			err = fmt.Errorf("vcbc sanity check: %v", r) //nolint: forbidigo // Wrapping a panic, not error.
		}
	}()

	ctx = log.WithTopic(ctx, "vcbc")

	log.Info(ctx, "Starting VCBC", z.Uint("id", v.Id))

	// === State ===

	var (
		hashFunction = sha256.New()

		messageByTag      = make(map[string][]byte)         // Store messages received by tag
		thresholdSigByTag = make(map[string]tbls.Signature) // Store final signature of messages by tag

		partialSigsBySource = make(map[int]tbls.Signature) // Store received partial signatures of my message

		alreadyUnicastReady = make(map[string]bool) // Store if I already sent ready to a specific tag
	)

	if m != nil {
		err := broadcast(VCBCMessage{
			Source: v.Id,
			Content: VCBCMessageContent{
				MsgType: MsgSend,
				Tag:     BuildTag(v.Id, v.Slot), // TODO: duty + slot
			},
			Message: m,
		})
		if err != nil {
			return err
		}
		log.Info(ctx, "Node id sent message", z.Uint("id", v.Id), z.Uint("slot", v.Slot))
	}

	for {
		select {
		case msg := <-receiveChannel:

			rule := classify(v.Slot, msg)
			switch rule {
			case UponSend:
				if !alreadyUnicastReady[msg.Content.Tag] {
					alreadyUnicastReady[msg.Content.Tag] = true

					messageByTag[msg.Content.Tag] = msg.Message

					// Reply with message hash
					hashFunction.Write(msg.Message)
					hash := hashFunction.Sum(nil)
					hashFunction.Reset()

					// Produce partial signature of message
					content := VCBCMessageContent{
						MsgType:     MsgReady,
						Tag:         msg.Content.Tag,
						MessageHash: hash,
					}
					encodedContent, err := json.Marshal(content)
					if err != nil {
						return err
					}
					partialSig, err := tbls.Sign(v.PrivKey, encodedContent)
					if err != nil {
						return err
					}

					err = unicast(msg.Source, VCBCMessage{
						Source:     v.Id,
						Content:    content,
						PartialSig: partialSig,
					})
					if err != nil {
						return err
					}
					log.Info(ctx, "Node id sent ready to source", z.Uint("id", v.Id), z.Uint("slot", v.Slot), z.Uint("source", msg.Source))
				}
			case UponReady:
				if partialSigsBySource[int(msg.Source)] == (tbls.Signature{}) {

					// Verify if partial signature matches message content
					encodedMessage, err := json.Marshal(msg.Content)
					if err != nil {
						return err
					}
					err = tbls.Verify(v.PubKeys[msg.Source], encodedMessage, msg.PartialSig)
					if err != nil {
						log.Info(ctx, "Node id received invalid ready signature from source", z.Uint("id", v.Id), z.Uint("slot", v.Slot), z.Uint("source", msg.Source))
						continue
					}

					partialSigsBySource[int(msg.Source)] = msg.PartialSig

					// If received enough partial sigs, aggregate and broadcast final signature
					if len(partialSigsBySource) == v.ThresholdPartialSigValue {
						thresholdSig, err := tbls.ThresholdAggregate(partialSigsBySource)
						if err != nil {
							return err
						}

						err = broadcast(VCBCMessage{
							Source: v.Id,
							Content: VCBCMessageContent{
								MsgType:     MsgFinal,
								Tag:         msg.Content.Tag,
								MessageHash: msg.Content.MessageHash,
							},
							ThresholdSig: thresholdSig,
						})
						if err != nil {
							return err
						}
						log.Info(ctx, "Node id sent final", z.Uint("id", v.Id), z.Uint("slot", v.Slot))
					}
				}
			case UponFinal:

				// Verify if final signature matches message content
				hashFunction.Write(messageByTag[msg.Content.Tag])
				hash := hashFunction.Sum(nil)
				hashFunction.Reset()

				content := VCBCMessageContent{
					MsgType:     MsgReady,
					Tag:         msg.Content.Tag,
					MessageHash: hash,
				}
				encodedContent, err := json.Marshal(content)
				if err != nil {
					return err
				}

				err = tbls.Verify(v.PubKey, encodedContent, msg.ThresholdSig)
				if err != nil {
					log.Info(ctx, "Node id received invalid final signature from source", z.Uint("id", v.Id), z.Uint("slot", v.Slot), z.Uint("source", msg.Source))
					continue
				}

				// Output result
				if slices.Compare(hash, msg.Content.MessageHash) == 0 && thresholdSigByTag[msg.Content.Tag] == (tbls.Signature{}) {
					thresholdSigByTag[msg.Content.Tag] = msg.ThresholdSig
					for _, sub := range v.Subs {
						sub(ctx, VCBCResult{
							Tag:     msg.Content.Tag,
							Message: messageByTag[msg.Content.Tag],
						})
					}
				}
			case UponRequest:
				if thresholdSigByTag[msg.Content.Tag] != (tbls.Signature{}) {
					err := unicast(msg.Source, VCBCMessage{
						Source: v.Id,
						Content: VCBCMessageContent{
							MsgType: MsgAnswer,
							Tag:     msg.Content.Tag,
						},
						Message:      messageByTag[msg.Content.Tag],
						ThresholdSig: thresholdSigByTag[msg.Content.Tag],
					})
					if err != nil {
						return err
					}
					log.Info(ctx, "Node id sent answer to source", z.Uint("id", v.Id), z.Uint("slot", v.Slot), z.Uint("source", msg.Source))
				}

			case UponAnswer:
				// Verify received signature
				hashFunction.Write(msg.Message)
				hash := hashFunction.Sum(nil)
				hashFunction.Reset()

				content := VCBCMessageContent{
					MsgType:     MsgReady,
					Tag:         msg.Content.Tag,
					MessageHash: hash,
				}
				encodedContent, err := json.Marshal(content)
				if err != nil {
					return err
				}

				err = tbls.Verify(v.PubKey, encodedContent, msg.ThresholdSig)
				if err != nil {
					log.Info(ctx, "Node id received invalid signature from source", z.Uint("id", v.Id), z.Uint("slot", v.Slot), z.Uint("source", msg.Source))
					continue
				}

				// Output result
				if thresholdSigByTag[msg.Content.Tag] == (tbls.Signature{}) {
					thresholdSigByTag[msg.Content.Tag] = msg.ThresholdSig
					log.Info(ctx, "Node id received answer", z.Uint("id", v.Id), z.Uint("slot", v.Slot))
					for _, sub := range v.Subs {
						sub(ctx, VCBCResult{
							Tag:     msg.Content.Tag,
							Message: msg.Message,
						})
					}
				}
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
