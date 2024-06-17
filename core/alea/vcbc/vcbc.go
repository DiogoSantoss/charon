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
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/alea/aba"
	"github.com/obolnetwork/charon/tbls"
	"google.golang.org/protobuf/types/known/anypb"
)

// Verifiable Consistent Broadcast from the paper: "Secure and Efficient Asynchronous Broadcast Protocols"
// Link: https://eprint.iacr.org/2001/006.pdf

type Transport[I any, V comparable] struct {
	Broadcast func(ctx context.Context,
		source int64, msgType MsgType, tag string, valueHash []byte, instance I, value V,
		partialSig tbls.Signature, thresholdSig tbls.Signature, sigs map[int64][]byte) error

	Unicast func(ctx context.Context, target int64,
		source int64, msgType MsgType, tag string, valueHash []byte, instance I, value V,
		partialSig tbls.Signature, thresholdSig tbls.Signature, sigs map[int64][]byte) error

	Receive <-chan VCBCMsg[I, V]

	// Optimization "CompleteView"
	BroadcastABA func(ctx context.Context, source int64, msgType aba.MsgType,
		instance I, agreementRound, round int64, estimative byte, values map[byte]struct{}) error

	Refill chan<- VCBCMsg[I, V]
}

type Definition[I any, V comparable] struct {
	BuildTag                 func(instance I, process int64) string
	IdFromTag                func(tag string) int64
	HashValue                func(value V) []byte
	SignData                 func(data []byte) (tbls.Signature, error)
	VerifySignature          func(process int64, data []byte, signature tbls.Signature) error
	VerifyAggregateSignature func(data []byte, signature tbls.Signature) error
	Subs                     []func(ctx context.Context, result VCBCResult[V]) error

	CompleteView            bool
	DelayVerification       bool
	MultiSignature          bool
	SignDataMultiSig        func(data []byte) ([]byte, error)
	VerifySignatureMultiSig func(process int64, data []byte, signature []byte) error

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

func (t MsgType) Valid() bool {
	return t > MsgUnknown && t < MsgAnswer
}

func (t MsgType) String() string {
	return typeLabels[t]
}

var typeLabels = map[MsgType]string{
	MsgUnknown: "unknown",
	MsgSend:    "send",
	MsgReady:   "ready",
	MsgFinal:   "final",
	MsgRequest: "request",
	MsgAnswer:  "answer",
}

type VCBCMsg[I any, V comparable] interface {
	Source() int64
	MsgType() MsgType
	Tag() string
	ValueHash() []byte
	Instance() I
	Value() V
	RealValue() *anypb.Any
	PartialSig() tbls.Signature
	ThresholdSig() tbls.Signature
	Signatures() map[int64][]byte
}

type UponRule int

func (r UponRule) String() string {
	return ruleLabels[r]
}

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

type VCBCResult[V comparable] struct {
	Tag    string
	Result V
}

type VCBCMessageContent struct {
	MsgType   MsgType
	Tag       string // Tag is an identifier of type: "ID.<id>.<instance>" where <id> is the sender id and <instance> is an instance identifier
	ValueHash []byte
}

func classify(msgType MsgType) UponRule {

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

	return t.Broadcast(ctx, process, MsgRequest, tag, nil, instance, zeroVal[V](), tbls.Signature{}, tbls.Signature{}, nil)
}

func zeroVal[V comparable]() V {
	var zero V
	return zero
}

func isZeroVal[V comparable](v V) bool {
	return v == zeroVal[V]()
}

func serializeContent(msgType MsgType, tag string, hashedValue []byte) ([]byte, error) {
	return json.Marshal(VCBCMessageContent{
		MsgType:   msgType,
		Tag:       tag,
		ValueHash: hashedValue,
	})
}

// Run executes the VCBC protocol
func Run[I any, V comparable](ctx context.Context, d Definition[I, V], t Transport[I, V], instance I, process int64, value V) (err error) {

	core.RecordStep(process-1, core.START_VCBC_SEND)

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

	// === State ===

	var (
		valueByTag        = make(map[string]V)              // Store values received by tag
		thresholdSigByTag = make(map[string]tbls.Signature) // Store final signature of value by tag

		partialSigsBySource = make(map[int]tbls.Signature) // Store received partial signatures of my value

		alreadyUnicastReady = make(map[string]bool) // Store if I already sent ready to a specific tag

		// Optimization "MultiSignature"
		signaturesByTag = make(map[string]map[int64][]byte) // Store map of signatures by tag
	)

	myTag := d.BuildTag(instance, process)

	if !isZeroVal(value) {
		err := t.Broadcast(ctx, process, MsgSend, myTag, nil, instance, value, tbls.Signature{}, tbls.Signature{}, nil)

		if err != nil {
			return err
		}
		log.Debug(ctx, "VCBC sent value", z.I64("id", process), z.Str("tag", myTag))
	}

	core.RecordStep(process-1, core.FINISH_VCBC_SEND)

	for {
		select {
		case msg := <-t.Receive:

			rule := classify(msg.MsgType())
			switch rule {
			case UponSend:
				core.RecordStep(process-1, core.START_VCBC_HANDLE_SEND)

				// Only reply once to each tag
				if !alreadyUnicastReady[msg.Tag()] {

					alreadyUnicastReady[msg.Tag()] = true
					valueByTag[msg.Tag()] = msg.Value()

					// Optimization "CompleteView": If all nodes broadcast the same value
					// then it is certain that this will be the outcome of the consensus.
					// Hence, we can send an early ABA finish message to speedup the agreement phase
					if d.CompleteView && len(valueByTag) == d.Nodes {
						log.Debug(ctx, "VCBC sent ABA finish", z.I64("id", process))
						// Send ABA Finish
						// TODO: AgreementRound and Round being zero
						// may be a problem since if VCBC takes too long
						// ABA may already have gone past round 0
						// thus making this useless
						err := t.BroadcastABA(ctx, process, aba.MsgFinish, instance, 0, 0, 1, nil)
						if err != nil {
							return err
						}
					}

					hash := d.HashValue(msg.Value())
					encodedContent, err := serializeContent(MsgReady, msg.Tag(), hash)
					if err != nil {
						return err
					}

					// Optimization "MultiSignature": To avoid expensive threshold signature aggregation
					// we can use ECDSA to produce a signature faster. The drawback is that later on
					// we will deal will array of signatures instead of a single one aggregated.
					if d.MultiSignature {

						sig, err := d.SignDataMultiSig(encodedContent)
						if err != nil {
							return err
						}
						err = t.Unicast(ctx, msg.Source(), process, MsgReady, msg.Tag(), hash, instance, zeroVal[V](), tbls.Signature{}, tbls.Signature{}, map[int64][]byte{process: sig})
						if err != nil {
							return err
						}

					} else {

						// <1s
						partialSig, err := d.SignData(encodedContent)
						if err != nil {
							return err
						}
						err = t.Unicast(ctx, msg.Source(), process, MsgReady, msg.Tag(), hash, instance, zeroVal[V](), partialSig, tbls.Signature{}, nil)
						if err != nil {
							return err
						}
					}

				}
				core.RecordStep(process-1, core.FINISH_VCBC_HANDLE_SEND)
			case UponReady:
				core.RecordStep(process-1, core.START_VCBC_HANDLE_READY)

				encodedMessage, err := serializeContent(msg.MsgType(), msg.Tag(), msg.ValueHash())
				if err != nil {
					return err
				}

				if d.MultiSignature && signaturesByTag[msg.Tag()][msg.Source()] == nil && msg.Tag() == myTag {

					if !d.DelayVerification {
						err = d.VerifySignatureMultiSig(msg.Source(), encodedMessage, msg.Signatures()[msg.Source()])
						if err != nil {
							log.Debug(ctx, "Node id received invalid ready signature from source", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
							continue
						}
					}

					if signaturesByTag[msg.Tag()] == nil {
						signaturesByTag[msg.Tag()] = make(map[int64][]byte)
					}

					// Store signature
					signaturesByTag[msg.Tag()][msg.Source()] = msg.Signatures()[msg.Source()]

					// If received enough sigs, broadcast set of final signature
					if len(signaturesByTag[msg.Tag()]) == d.ThresholdPartialSigValue() {

						if d.DelayVerification {
							for source := range signaturesByTag[msg.Tag()] {
								err = d.VerifySignatureMultiSig(int64(source), encodedMessage, signaturesByTag[msg.Tag()][source])
								if err != nil {
									log.Debug(ctx, "VCBC invalid signature detected by node", z.I64("id", process), z.Str("tag", msg.Tag()), z.Int("node", int(source)))
									delete(signaturesByTag[msg.Tag()], source)
								}
							}

							// Some signatures were invalid, we must wait for more
							if len(signaturesByTag[msg.Tag()]) < d.ThresholdPartialSigValue() {
								continue
							}
						}

						cloneSignaturesByTag := make(map[int64][]byte)
						for source, sig := range signaturesByTag[msg.Tag()] {
							cloneSignaturesByTag[source] = sig
						}

						err = t.Broadcast(ctx, process, MsgFinal, msg.Tag(), msg.ValueHash(), instance, valueByTag[msg.Tag()], tbls.Signature{}, tbls.Signature{}, cloneSignaturesByTag)

						if err != nil {
							return err
						}
						log.Debug(ctx, "VCBC sent final", z.I64("id", process), z.Str("tag", msg.Tag()))
					}

				} else if !d.MultiSignature && partialSigsBySource[int(msg.Source())] == (tbls.Signature{}) && msg.Tag() == myTag {

					// With delay verification, we only verify the final signature
					if !d.DelayVerification {
						// [1,1.5]s
						err = d.VerifySignature(msg.Source(), encodedMessage, msg.PartialSig())
						if err != nil {
							log.Debug(ctx, "Node id received invalid ready signature from source", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
							continue
						}
					}

					partialSigsBySource[int(msg.Source())] = msg.PartialSig()

					// If received enough partial sigs, aggregate and broadcast final signature
					if len(partialSigsBySource) == d.ThresholdPartialSigValue() {
						// <1s
						thresholdSig, err := tbls.ThresholdAggregate(partialSigsBySource)
						if err != nil {
							return err
						}

						// Threshold aggregate does not return error if partial sigs are invalid
						// Hence, with delay verification, we must verify if the result is valid
						// and discard the invalid partial sigs
						if d.DelayVerification {

							// [1,1.5]s
							err = d.VerifyAggregateSignature(encodedMessage, thresholdSig)
							if err != nil {
								for source := range partialSigsBySource {
									err = d.VerifySignature(int64(source), encodedMessage, partialSigsBySource[source])
									if err != nil {
										log.Debug(ctx, "VCBC invalid signature detected by node", z.I64("id", process), z.Str("tag", msg.Tag()), z.Int("node", source))
										delete(partialSigsBySource, source)
									}
								}
								continue
							}
						}

						err = t.Broadcast(ctx, process, MsgFinal, msg.Tag(), msg.ValueHash(), instance, valueByTag[msg.Tag()], tbls.Signature{}, thresholdSig, nil)

						if err != nil {
							return err
						}
						log.Debug(ctx, "VCBC sent final", z.I64("id", process), z.Str("tag", msg.Tag()))
					}
				}
				core.RecordStep(process-1, core.FINISH_VCBC_HANDLE_READY)
			case UponFinal:

				core.RecordStep(process-1, core.START_VCBC_HANDLE_FINISH)

				value, ok := valueByTag[msg.Tag()]
				if !ok {
					log.Debug(ctx, "Node id received final before send", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
					go func() { t.Refill <- msg }()
					continue
				}

				// Verify if final signature matches message content
				hash := d.HashValue(value)
				encodedContent, err := serializeContent(MsgReady, msg.Tag(), hash)
				if err != nil {
					return err
				}

				if d.MultiSignature {
					// Must receive threshold number of signatures
					if len(msg.Signatures()) < d.ThresholdPartialSigValue() {
						log.Debug(ctx, "Node id did not receive enough signatures", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
						continue
					}

					// Verify all signatures
					for source, sig := range msg.Signatures() {
						err = d.VerifySignatureMultiSig(int64(source), encodedContent, sig)
						if err != nil {
							log.Debug(ctx, "Node id received invalid final signature from source", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
							continue
						}
					}

					if slices.Compare(hash, msg.ValueHash()) == 0 {

						if signaturesByTag[msg.Tag()] == nil {
							signaturesByTag[msg.Tag()] = make(map[int64][]byte)
						}
						// Fill in missing signatures
						for source, sig := range msg.Signatures() {
							if signaturesByTag[msg.Tag()][int64(source)] == nil {
								signaturesByTag[msg.Tag()][int64(source)] = sig
							}
						}

						log.Debug(ctx, "VCBC received final", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
						core.RecordStep(process-1, core.START_VCBC_SUBS)
						for _, sub := range d.Subs {
							err := sub(ctx, VCBCResult[V]{
								Tag:    msg.Tag(),
								Result: value,
							})
							if err != nil {
								return err
							}
						}
						core.RecordStep(process-1, core.FINISH_VCBC_SUBS)
					}
				} else {
					// [1,1.5]s
					err = d.VerifyAggregateSignature(encodedContent, msg.ThresholdSig())
					if err != nil {
						log.Debug(ctx, "Node id received invalid final signature from source", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
						continue
					}

					// Output result
					if slices.Compare(hash, msg.ValueHash()) == 0 && thresholdSigByTag[msg.Tag()] == (tbls.Signature{}) {
						thresholdSigByTag[msg.Tag()] = msg.ThresholdSig()

						log.Debug(ctx, "VCBC received final", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
						core.RecordStep(process-1, core.START_VCBC_SUBS)
						for _, sub := range d.Subs {
							err := sub(ctx, VCBCResult[V]{
								Tag:    msg.Tag(),
								Result: valueByTag[msg.Tag()],
							})
							if err != nil {
								return err
							}
						}
						core.RecordStep(process-1, core.FINISH_VCBC_SUBS)
					}
				}

				core.RecordStep(process-1, core.FINISH_VCBC_HANDLE_FINISH)
			case UponRequest:
				if d.MultiSignature {

					if signaturesByTag[msg.Tag()] != nil && len(signaturesByTag[msg.Tag()]) >= d.ThresholdPartialSigValue() {
						err := t.Broadcast(ctx, process, MsgFinal, msg.Tag(), d.HashValue(valueByTag[msg.Tag()]), instance, valueByTag[msg.Tag()], tbls.Signature{}, tbls.Signature{}, signaturesByTag[msg.Tag()])
						if err != nil {
							return err
						}
						log.Debug(ctx, "VCBC sent answer", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
					} else {
						log.Debug(ctx, "VCBC no answer to request", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
					}
				} else {

					if thresholdSigByTag[msg.Tag()] != (tbls.Signature{}) {
						err := t.Unicast(ctx, msg.Source(), process, MsgAnswer, msg.Tag(), nil, instance, valueByTag[msg.Tag()], tbls.Signature{}, thresholdSigByTag[msg.Tag()], nil)
						if err != nil {
							return err
						}
						log.Debug(ctx, "VCBC sent answer", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
					} else {
						log.Debug(ctx, "VCBC no answer to request", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
					}
				}

			case UponAnswer:
				// Verify received signature
				hash := d.HashValue(msg.Value())

				content := VCBCMessageContent{
					MsgType:   MsgReady,
					Tag:       msg.Tag(),
					ValueHash: hash,
				}
				encodedContent, err := json.Marshal(content)
				if err != nil {
					return err
				}

				if d.MultiSignature {

					// Verify all signatures
					if len(msg.Signatures()) < d.ThresholdPartialSigValue() {
						log.Debug(ctx, "Node id did not receive enough signatures", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
						continue
					}

					// TODO: Maybe we could accept answers that have threshold valid signatures even if they have some invalid ones
					for source, sig := range msg.Signatures() {
						err = d.VerifySignatureMultiSig(int64(source), encodedContent, sig)
						if err != nil {
							log.Debug(ctx, "Node id received invalid answer signature from source", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
							continue
						}
					}

					signaturesByTag[msg.Tag()] = msg.Signatures()
					log.Debug(ctx, "VCBC received answer", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
					for _, sub := range d.Subs {
						err := sub(ctx, VCBCResult[V]{
							Tag:    msg.Tag(),
							Result: msg.Value(),
						})
						if err != nil {
							return err
						}
					}

				} else {

					err = d.VerifyAggregateSignature(encodedContent, msg.ThresholdSig())
					if err != nil {
						log.Debug(ctx, "Node id received invalid signature from source", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
						continue
					}

					// Output result
					if thresholdSigByTag[msg.Tag()] == (tbls.Signature{}) {
						thresholdSigByTag[msg.Tag()] = msg.ThresholdSig()
						log.Debug(ctx, "VCBC received answer", z.I64("id", process), z.I64("source", msg.Source()), z.Str("tag", msg.Tag()))
						for _, sub := range d.Subs {
							err := sub(ctx, VCBCResult[V]{
								Tag:    msg.Tag(),
								Result: msg.Value(),
							})
							if err != nil {
								return err
							}
						}
					}

				}
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
