package vcbc

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
)

// Verifiable Consistent Broadcast from the paper: "Secure and Efficient Asynchronous Broadcast Protocols"
// Link: https://eprint.iacr.org/2001/006.pdf

type Transport[I any, V comparable] struct {
	Broadcast func(ctx context.Context, msg VCBCMessage[I, V]) error
	Unicast   func(ctx context.Context, target int64, msg VCBCMessage[I, V]) error
	Receive   <-chan VCBCMessage[I, V]
}

type Definition[I any, V comparable] struct {
	BuildTag                 func(instance I, process int64) string
	IdFromTag                func(tag string) int64
	HashValue                func(value V) []byte
	SignData                 func(data []byte) (tbls.Signature, error)
	VerifySignature          func(process int64, data []byte, signature tbls.Signature) error
	VerifyAggregateSignature func(data []byte, signature tbls.Signature) error
	Subs                     []func(ctx context.Context, result VCBCResult[V]) error

	Nodes int
}

// Faulty returns the maximum number of faulty nodes supported in the system
func (d Definition[I, V]) Faulty() int {
	return int(math.Floor(float64(d.Nodes-1) / 3))
}

// Threshold returns the number of necessary signatures to aggregate a threshold signature
func (d Definition[I, V]) ThresholdPartialSigValue() int {
	return int(math.Ceil((float64(d.Nodes) + float64(d.Faulty()) + 1) / 2))
}

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

type VCBCResult[V comparable] struct {
	Tag    string
	Result V
}

type VCBCMessageContent struct {
	MsgType   MsgType
	Tag       string // Tag is an identifier of type: "ID.<id>.<instance>" where <id> is the sender id and <instance> is an instance identifier
	ValueHash []byte
}

type VCBCMessage[I any, V comparable] struct {
	Source       int64
	Content      VCBCMessageContent // Separate struct for content to allow partial signatures on specific content only
	Instance     I
	Value        V
	PartialSig   tbls.Signature
	ThresholdSig tbls.Signature
}

func classify(msgType MsgType) UponRule {

	// TODO do we need to ensure that we are not processing messages from other instances ?

	switch msgType {
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

// BroadcastRequest sends a request to all nodes for a value with a specific tag
// It can only be called after Run has been started since the response is expected to be handled by the Run function
func BroadcastRequest[I any, V comparable](ctx context.Context, d Definition[I, V], t Transport[I, V], instance I, process int64, tag string) error {

	ctx = log.WithTopic(ctx, "vcbc")

	log.Debug(ctx, "VCBC Request", z.I64("id", process), z.Str("tag", tag))

	return t.Broadcast(ctx, VCBCMessage[I, V]{
		Source:   process,
		Instance: instance,
		Content: VCBCMessageContent{
			MsgType: MsgRequest,
			Tag:     tag,
		},
	})
}

func zeroVal[V comparable]() V {
	var zero V
	return zero
}

func isZeroVal[V comparable](v V) bool {
	return v == zeroVal[V]()
}

// Run executes the VCBC protocol
func Run[I any, V comparable](ctx context.Context, d Definition[I, V], t Transport[I, V], instance I, process int64, value V) (err error) {

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

	log.Debug(ctx, "Starting VCBC", z.I64("id", process))

	// === State ===

	var (
		messageByTag      = make(map[string]V)              // Store messages received by tag
		thresholdSigByTag = make(map[string]tbls.Signature) // Store final signature of messages by tag

		partialSigsBySource = make(map[int]tbls.Signature) // Store received partial signatures of my value

		alreadyUnicastReady = make(map[string]bool) // Store if I already sent ready to a specific tag
	)

	myTag := d.BuildTag(instance, process)

	if !isZeroVal(value) {
		err := t.Broadcast(ctx, VCBCMessage[I, V]{
			Source:   process,
			Instance: instance,
			Content: VCBCMessageContent{
				MsgType: MsgSend,
				Tag:     myTag,
			},
			Value: value,
		})
		if err != nil {
			return err
		}
		log.Debug(ctx, "VCBC sent value", z.I64("id", process), z.Str("tag", myTag))
	}

	for {
		select {
		case msg := <-t.Receive:

			rule := classify(msg.Content.MsgType)
			switch rule {
			case UponSend:
				if !alreadyUnicastReady[msg.Content.Tag] {
					alreadyUnicastReady[msg.Content.Tag] = true

					messageByTag[msg.Content.Tag] = msg.Value

					hash := d.HashValue(msg.Value)

					// Produce partial signature of message
					content := VCBCMessageContent{
						MsgType:   MsgReady,
						Tag:       msg.Content.Tag,
						ValueHash: hash,
					}
					encodedContent, err := json.Marshal(content)
					if err != nil {
						return err
					}
					partialSig, err := d.SignData(encodedContent)
					if err != nil {
						return err
					}

					err = t.Unicast(ctx, msg.Source, VCBCMessage[I, V]{
						Source:     process,
						Instance:   instance,
						Content:    content,
						PartialSig: partialSig,
					})
					if err != nil {
						return err
					}
					log.Debug(ctx, "VCBC sent ready", z.I64("id", process), z.I64("source", msg.Source), z.Str("tag", msg.Content.Tag))
				}
			case UponReady:
				if partialSigsBySource[int(msg.Source)] == (tbls.Signature{}) && msg.Content.Tag == myTag {

					// Verify if partial signature matches message content
					encodedMessage, err := json.Marshal(msg.Content)
					if err != nil {
						return err
					}
					err = d.VerifySignature(msg.Source, encodedMessage, msg.PartialSig)
					if err != nil {
						log.Debug(ctx, "Node id received invalid ready signature from source", z.I64("id", process), z.I64("source", msg.Source), z.Str("tag", msg.Content.Tag))
						continue
					}

					partialSigsBySource[int(msg.Source)] = msg.PartialSig

					// If received enough partial sigs, aggregate and broadcast final signature
					if len(partialSigsBySource) == d.ThresholdPartialSigValue() {
						thresholdSig, err := tbls.ThresholdAggregate(partialSigsBySource)
						if err != nil {
							return err
						}

						err = t.Broadcast(ctx, VCBCMessage[I, V]{
							Source:   process,
							Instance: instance,
							Content: VCBCMessageContent{
								MsgType:   MsgFinal,
								Tag:       msg.Content.Tag,
								ValueHash: msg.Content.ValueHash,
							},
							ThresholdSig: thresholdSig,
						})
						if err != nil {
							return err
						}
						log.Debug(ctx, "VCBC sent final", z.I64("id", process), z.Str("tag", msg.Content.Tag))
					}
				}
			case UponFinal:

				// Verify if final signature matches message content
				hash := d.HashValue(messageByTag[msg.Content.Tag])

				content := VCBCMessageContent{
					MsgType:   MsgReady,
					Tag:       msg.Content.Tag,
					ValueHash: hash,
				}
				encodedContent, err := json.Marshal(content)
				if err != nil {
					return err
				}

				err = d.VerifyAggregateSignature(encodedContent, msg.ThresholdSig)
				if err != nil {
					log.Debug(ctx, "Node id received invalid final signature from source", z.I64("id", process), z.I64("source", msg.Source), z.Str("tag", msg.Content.Tag))
					continue
				}

				// Output result
				if slices.Compare(hash, msg.Content.ValueHash) == 0 && thresholdSigByTag[msg.Content.Tag] == (tbls.Signature{}) {
					thresholdSigByTag[msg.Content.Tag] = msg.ThresholdSig

					log.Debug(ctx, "VCBC received final", z.I64("id", process), z.Str("tag", msg.Content.Tag))
					for _, sub := range d.Subs {
						err := sub(ctx, VCBCResult[V]{
							Tag:    msg.Content.Tag,
							Result: messageByTag[msg.Content.Tag],
						})
						if err != nil {
							return err
						}
					}
				}
			case UponRequest:
				if thresholdSigByTag[msg.Content.Tag] != (tbls.Signature{}) {
					err := t.Unicast(ctx, msg.Source, VCBCMessage[I, V]{
						Source:   process,
						Instance: instance,
						Content: VCBCMessageContent{
							MsgType: MsgAnswer,
							Tag:     msg.Content.Tag,
						},
						Value:        messageByTag[msg.Content.Tag],
						ThresholdSig: thresholdSigByTag[msg.Content.Tag],
					})
					if err != nil {
						return err
					}
					log.Debug(ctx, "VCBC sent answer", z.I64("id", process), z.I64("source", msg.Source), z.Str("tag", msg.Content.Tag))
				}

			case UponAnswer:

				// Verify received signature
				hash := d.HashValue(msg.Value)

				content := VCBCMessageContent{
					MsgType:   MsgReady,
					Tag:       msg.Content.Tag,
					ValueHash: hash,
				}
				encodedContent, err := json.Marshal(content)
				if err != nil {
					return err
				}

				err = d.VerifyAggregateSignature(encodedContent, msg.ThresholdSig)
				if err != nil {
					log.Debug(ctx, "Node id received invalid signature from source", z.I64("id", process), z.I64("source", msg.Source), z.Str("tag", msg.Content.Tag))
					continue
				}

				// Output result
				if thresholdSigByTag[msg.Content.Tag] == (tbls.Signature{}) {
					thresholdSigByTag[msg.Content.Tag] = msg.ThresholdSig
					log.Debug(ctx, "VCBC received answer", z.I64("id", process), z.I64("source", msg.Source), z.Str("tag", msg.Content.Tag))
					for _, sub := range d.Subs {
						err := sub(ctx, VCBCResult[V]{
							Tag:    msg.Content.Tag,
							Result: msg.Value,
						})
						if err != nil {
							return err
						}
					}
				}
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
