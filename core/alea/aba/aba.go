package aba

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core/alea/commoncoin"
)

// Asynchronous Binary Agreement implementation fro	m the paper: "Cobalt: BFT Governance in Open Networks"
// Link: https://arxiv.org/pdf/1802.07240.pdf (Page 19/20)

type ABAMsg[I any] interface {
	MsgType() MsgType
	Source() int64
	Instance() I
	AgreementRound() int64
	Round() int64
	Estimative() byte
	Values() map[byte]struct{}

	CloneToInit() ABAMsg[I]
}

type Transport[I any] struct {
	Broadcast func(ctx context.Context, source int64, msgType MsgType,
		instance I, agreementRound, round int64, estimative byte,
		values map[byte]struct{}) error
	Receive <-chan ABAMsg[I]
	Refill  chan<- ABAMsg[I]
}

type Definition struct {
	FastABA   bool
	AsyncCoin bool
	Nodes     int
}

func (d Definition) Faulty() int {
	return int(math.Floor(float64(d.Nodes-1) / 3))
}

func (d Definition) BigQuorum() int {
	return 2*d.Faulty() + 1
}

func (d Definition) SmallQuorum() int {
	return d.Faulty() + 1
}

func (d Definition) CorrectNodes() int {
	return d.Nodes - d.Faulty()
}

type MsgType uint

const (
	MsgUnknown MsgType = iota
	MsgInput
	MsgInit
	MsgAux
	MsgConf
	MsgFinish
)

var typeLabels = map[MsgType]string{
	MsgUnknown: "unknown",
	MsgInput:   "input",
	MsgInit:    "init",
	MsgAux:     "aux",
	MsgConf:    "conf",
	MsgFinish:  "finish",
}

func (t MsgType) Valid() bool {
	return t > MsgUnknown && t < MsgFinish
}

func (t MsgType) String() string {
	return typeLabels[t]
}

type UponRule uint

const (
	UponNothing UponRule = iota
	UponWeakSupportInit
	UponStrongSupportInit
	UponFastABA
	UponSupportAux
	UponSupportConf
	UponWeakSupportFinish
	UponStrongSupportFinish
)

var ruleLabels = map[UponRule]string{
	UponNothing:             "nothing",
	UponWeakSupportInit:     "weak_support_init",
	UponStrongSupportInit:   "strong_support_init",
	UponFastABA:             "fast_aba",
	UponSupportAux:          "support_aux",
	UponSupportConf:         "support_conf",
	UponWeakSupportFinish:   "weak_support_finish",
	UponStrongSupportFinish: "strong_support_finish",
}

func (r UponRule) String() string {
	return ruleLabels[r]
}

func equalValues(a, b map[byte]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, exists := b[k]; !exists {
			return false
		}
	}
	return true
}

func equal[I any](a, b ABAMsg[I]) bool {
	return a.MsgType() == b.MsgType() &&
		a.Source() == b.Source() &&
		a.AgreementRound() == b.AgreementRound() &&
		a.Round() == b.Round() &&
		a.Estimative() == b.Estimative() &&
		equalValues(a.Values(), b.Values())
}

func containsMsg[I any](msgs []ABAMsg[I], msg ABAMsg[I]) bool {
	for _, m := range msgs {
		if equal(m, msg) {
			return true
		}
	}
	return false
}

// Returns the triggered upon rule by the received message
func classify[I any](d Definition, msg ABAMsg[I], values map[byte]struct{}, receivedInput map[int64][]ABAMsg[I], receivedInit map[int64][]ABAMsg[I], receivedAux map[int64][]ABAMsg[I], receivedConf map[int64][]ABAMsg[I], receivedFinish map[int64][]ABAMsg[I]) UponRule {

	switch msg.MsgType() {
	case MsgInit:
		inits := filterByRoundAndValue(flatten(receivedInit), msg.Round(), msg.Estimative())
		if d.FastABA && len(filterByRoundAndValue(flatten(receivedInput), msg.Round(), msg.Estimative())) >= d.Nodes {
			return UponFastABA
		} else if len(inits) >= d.BigQuorum() {
			return UponStrongSupportInit
		} else if len(inits) >= d.SmallQuorum() {
			return UponWeakSupportInit
		}
	case MsgAux:
		auxs := filterByRoundAndValues(flatten(receivedAux), msg.Round(), setToArray(values))
		if len(auxs) >= d.CorrectNodes() {
			return UponSupportAux
		}
	case MsgConf:
		confs := filterByRoundAndSubsetValues(flatten(receivedConf), msg.Round(), values)
		if len(confs) >= d.CorrectNodes() {
			return UponSupportConf
		}
	case MsgFinish:
		finishes := filterByValue(flatten(receivedFinish), msg.Estimative())
		if len(finishes) >= d.BigQuorum() {
			return UponStrongSupportFinish
		} else if len(finishes) >= d.SmallQuorum() {
			return UponWeakSupportFinish
		}
	default:
		panic("bug: invalid message type")
	}

	return UponNothing
}

func isContextErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func Run[I any](ctx context.Context, d Definition, t Transport[I], dCoin commoncoin.Definition[I], tCoin commoncoin.Transport[I], instance I, process int64, agreementRound int64, valueInput byte) (result byte, err error) {

	defer func() {
		// Panics are used for assertions and sanity checks to reduce lines of code
		// and to improve readability. Catch them here.
		if r := recover(); r != nil {
			if !strings.Contains(fmt.Sprint(r), "bug") {
				panic(r) // Only catch internal sanity checks.
			}
			err = fmt.Errorf("aba sanity check: %v", r) //nolint: forbidigo // Wrapping a panic, not error.
		}
	}()

	ctx = log.WithTopic(ctx, "aba")

	// === State ===
	var (
		estimative = make(map[int64]byte)
		values     = make(map[int64]map[byte]struct{})

		coinResult      = make(map[int64]byte)
		coinResultMutex sync.Mutex
		coinResultCh    = make(chan struct{})

		alreadyBroadcastedInit        = make(map[int64]bool)
		alreadyBroadcastedAux         = make(map[int64]bool)
		alreadyBroadcastedFinish bool = false

		receivedInput  = make(map[int64][]ABAMsg[I])
		receivedInit   = make(map[int64][]ABAMsg[I])
		receivedAux    = make(map[int64][]ABAMsg[I])
		receivedConf   = make(map[int64][]ABAMsg[I])
		receivedFinish = make(map[int64][]ABAMsg[I])
	)

	// Store received messages and returns true if the message is new
	// If the message is already stored, no need to handle it
	storeMessage := func(msg ABAMsg[I]) bool {
		// Print address
		switch msg.MsgType() {
		case MsgInput:
			// Store both as INPUT and INIT
			if !containsMsg(receivedInput[msg.Source()], msg) {
				receivedInput[msg.Source()] = append(receivedInput[msg.Source()], msg)

				msgCopy := msg.CloneToInit()
				if !containsMsg(receivedInit[msg.Source()], msgCopy) {
					receivedInit[msg.Source()] = append(receivedInit[msg.Source()], msgCopy)
				}
				return true
			}
		case MsgInit:
			if !containsMsg(receivedInit[msg.Source()], msg) {
				receivedInit[msg.Source()] = append(receivedInit[msg.Source()], msg)
				return true
			}
		case MsgAux:
			if !containsMsg(receivedAux[msg.Source()], msg) {
				receivedAux[msg.Source()] = append(receivedAux[msg.Source()], msg)
				return true
			}
		case MsgConf:
			if !containsMsg(receivedConf[msg.Source()], msg) {
				receivedConf[msg.Source()] = append(receivedConf[msg.Source()], msg)
				return true
			}
		case MsgFinish:
			if !containsMsg(receivedFinish[msg.Source()], msg) {
				receivedFinish[msg.Source()] = append(receivedFinish[msg.Source()], msg)
				return true
			}
		default:
			panic("bug: invalid message type")
		}
		return false
	}

	computeCoin := func(round int64) {
		coinValue, err := commoncoin.SampleCoin(ctx, dCoin, tCoin, instance, agreementRound, round, process) // Algorithm 1:9
		if err != nil && !isContextErr(err) {
			log.Debug(ctx, "Error computing common coin", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", round), z.Err(err))
			return
		}
		coinResultMutex.Lock()
		coinResult[round] = coinValue
		close(coinResultCh)
		coinResultCh = make(chan struct{})
		coinResultMutex.Unlock()
	}

	alreadyBroadcastedInit[0] = true
	values[0] = make(map[byte]struct{})

	// === Algorithm ===
	estimative[0] = valueInput // Algorithm 1:3

	log.Debug(ctx, "ABA estimative", z.I64("id", process), z.I64("agreementRound", agreementRound), z.U8("estimative", estimative[0]))

	{ // Algorithm 1:4
		err := t.Broadcast(ctx, process, MsgInput, instance, agreementRound, 0, estimative[0], nil)
		if err != nil {
			return 0, err
		}
	}

	if d.AsyncCoin {
		go computeCoin(0) // Optimization 1
	}

	for {
		select {
		case msg := <-t.Receive:

			// Message from past agreement round, don't need to handle it since locally already moved to the next round
			if msg.AgreementRound() < agreementRound {
				continue
				// Message from future agreement round, refill channel to handle it later
			} else if msg.AgreementRound() > agreementRound {
				go func() { t.Refill <- msg }()
				break
			}

			if !storeMessage(msg) {
				break
			}

			// TODO: There is a problem with using the CompleteView optimization with DelayABA
			// VCBC may broadcast a ABAfinish **after** he already broadcasted ABAfinish (for another value)
			// if the node has not yet broadcasted then we can use this little hack, otherwise consensus may not finish
			// or may decide diferent values
			// Fixing this would imply that VCBC knows about state regarding ABA which is currently not possible
			if msg.MsgType() == MsgFinish && msg.Source() == process && !alreadyBroadcastedFinish {
				alreadyBroadcastedFinish = true
			}

			// Handle INPUT messages as INIT messages
			if msg.MsgType() == MsgInput {
				msg = msg.CloneToInit()
			}

			rule := classify(d, msg, values[msg.Round()], receivedInput, receivedInit, receivedAux, receivedConf, receivedFinish)
			if rule == UponNothing {
				break
			}

			switch rule {
			case UponWeakSupportFinish: // Algorithm 1:1
				if !alreadyBroadcastedFinish {
					log.Debug(ctx, "ABA upon rule triggered", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", msg.Round()), z.Any("rule", rule))

					alreadyBroadcastedFinish = true
					err := t.Broadcast(ctx, process, msg.MsgType(), msg.Instance(),
						msg.AgreementRound(), msg.Round(), msg.Estimative(), msg.Values())
					if err != nil {
						return 0, err
					}
				}

			case UponStrongSupportFinish: // Algorithm 1:2
				log.Debug(ctx, "ABA upon rule triggered", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", msg.Round()), z.Any("rule", rule))
				return msg.Estimative(), nil //  TODO perhaps nodes should not return and instead keep running (forever?)

			case UponWeakSupportInit: // Algorithm 1:5
				log.Debug(ctx, "ABA upon rule triggered", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", msg.Round()), z.Any("rule", rule), z.Any("estimative", msg.Estimative()))
				err := t.Broadcast(ctx, process, msg.MsgType(), msg.Instance(),
					msg.AgreementRound(), msg.Round(), msg.Estimative(), msg.Values())
				if err != nil {
					return 0, err
				}

			case UponStrongSupportInit: // Algorithm 1:6
				if values[msg.Round()] == nil {
					values[msg.Round()] = make(map[byte]struct{})
				}
				values[msg.Round()][msg.Estimative()] = struct{}{}
				if !alreadyBroadcastedAux[msg.Round()] {
					log.Debug(ctx, "ABA upon rule triggered", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", msg.Round()), z.Any("rule", rule), z.Any("estimative", msg.Estimative()))
					alreadyBroadcastedAux[msg.Round()] = true
					err := t.Broadcast(ctx, process, MsgAux, instance, agreementRound, msg.Round(), msg.Estimative(), nil)
					if err != nil {
						return 0, err
					}
				} else {
					log.Debug(ctx, "ABA already broadcasted aux", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", msg.Round()), z.Any("rule", rule), z.Any("estimative", msg.Estimative()))
				}

				// Since values set may have changed, verify if it is possible to broadcast CONF based on existing AUX messages
				auxs := filterByRoundAndValues(flatten(receivedAux), msg.Round(), setToArray(values[msg.Round()]))
				if len(auxs) >= d.CorrectNodes() {
					log.Debug(ctx, "ABA upon rule triggered", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", msg.Round()), z.Any("rule", rule), z.Any("values", values[msg.Round()]))
					values_copy := make(map[byte]struct{})
					for k, v := range values[msg.Round()] {
						values_copy[k] = v
					}
					// byte(0) is unused
					err := t.Broadcast(ctx, process, MsgConf, instance, agreementRound, msg.Round(), byte(0), values_copy)
					if err != nil {
						return 0, err
					}
				}

			case UponFastABA: // Optimization 2
				if values[msg.Round()] == nil {
					values[msg.Round()] = make(map[byte]struct{})
				}
				values[msg.Round()][msg.Estimative()] = struct{}{}

				if !alreadyBroadcastedFinish {
					log.Debug(ctx, "ABA upon rule triggered", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", msg.Round()), z.Any("rule", rule))
					alreadyBroadcastedFinish = true
					estimative[msg.Round()+1] = msg.Estimative()
					err := t.Broadcast(ctx, process, MsgFinish, instance, agreementRound, msg.Round(), msg.Estimative(), nil)
					if err != nil {
						return 0, err
					}

					// Equivalent to "return to step 4" in Algorithm 1:10
					next_round := msg.Round() + 1

					if !alreadyBroadcastedInit[next_round] {

						alreadyBroadcastedInit[next_round] = true
						if values[next_round] == nil {
							values[next_round] = make(map[byte]struct{})
						}

						log.Debug(ctx, "ABA new round estimative", z.I64("id", process), z.I64("agreementRound", msg.AgreementRound()), z.I64("abaRound", next_round), z.U8("estimative", estimative[next_round]))
						err := t.Broadcast(ctx, process, MsgInput, instance, agreementRound, next_round, estimative[next_round], nil)
						if err != nil {
							return 0, err
						}

						if d.AsyncCoin {
							go computeCoin(next_round)
						}
					}
				}

			case UponSupportAux: // Algorithm 1:7
				// TODO Why does this solve the data race?? sending values[msg.Round()] should be a copy, not the same reference
				log.Debug(ctx, "ABA upon rule triggered", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", msg.Round()), z.Any("rule", rule), z.Any("values", values[msg.Round()]))
				values_copy := make(map[byte]struct{})
				for k, v := range values[msg.Round()] {
					values_copy[k] = v
				}
				// byte(0) is unused
				err := t.Broadcast(ctx, process, MsgConf, instance, agreementRound, msg.Round(), byte(0), values_copy)
				if err != nil {
					return 0, err
				}

			case UponSupportConf: // Algorithm 1:8

				log.Debug(ctx, "ABA upon rule triggered", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", msg.Round()), z.Any("rule", rule), z.Any("values", values[msg.Round()]))

				var (
					sr     byte
					exists bool
				)
				// AsyncCoin must wait for asynchronous call to finish
				if d.AsyncCoin {
					coinResultMutex.Lock()
					sr, exists = coinResult[msg.Round()]
					ch := coinResultCh
					coinResultMutex.Unlock()

					for !exists {
						select {
						case <-ctx.Done():
							log.Debug(ctx, "Context done, did not finish common coin", z.I64("id", process), z.I64("agreementRound", agreementRound))
							return 0, ctx.Err()
						case <-ch:
							coinResultMutex.Lock()
							sr, exists = coinResult[msg.Round()]
							ch = coinResultCh
							coinResultMutex.Unlock()
						}
					}
					// Not AsyncCoin, calls blocking function
				} else {
					sr, exists = coinResult[msg.Round()]
					if !exists {
						coinValue, err := commoncoin.SampleCoin(ctx, dCoin, tCoin, instance, agreementRound, msg.Round(), process) // Algorithm 1:9
						if err != nil {
							return 0, err
						}
						sr = coinValue
						coinResult[msg.Round()] = coinValue
					}
				}

				//Algorithm 1:10
				if len(values[msg.Round()]) == 2 {
					estimative[msg.Round()+1] = sr
					log.Debug(ctx, "ABA two values", z.I64("id", process), z.I64("agreementRound", msg.AgreementRound()), z.I64("abaRound", msg.Round()))

				} else if len(values[msg.Round()]) == 1 {
					var value byte
					for k := range values[msg.Round()] {
						value = k
					}

					estimative[msg.Round()+1] = value

					if (value == sr) && (!alreadyBroadcastedFinish) {
						log.Debug(ctx, "ABA value matches coin", z.I64("id", process), z.I64("agreementRound", msg.AgreementRound()), z.I64("abaRound", msg.Round()), z.U8("value", value))
						alreadyBroadcastedFinish = true
						err := t.Broadcast(ctx, process, MsgFinish, instance, agreementRound, msg.Round(), sr, nil)
						if err != nil {
							return 0, err
						}
					} else if (value == sr) && (alreadyBroadcastedFinish) {
						log.Debug(ctx, "ABA already broadcasted finish", z.I64("id", process), z.I64("agreementRound", msg.AgreementRound()), z.I64("abaRound", msg.Round()), z.U8("value", value))
					}
				}

				// Equivalent to "return to step 4" in Algorithm 1:10
				next_round := msg.Round() + 1

				if !alreadyBroadcastedInit[next_round] {

					alreadyBroadcastedInit[next_round] = true
					if values[next_round] == nil {
						values[next_round] = make(map[byte]struct{})
					}

					log.Debug(ctx, "ABA new round estimative", z.I64("id", process), z.I64("agreementRound", msg.AgreementRound()), z.I64("abaRound", next_round), z.U8("estimative", estimative[next_round]))
					err := t.Broadcast(ctx, process, MsgInput, instance, agreementRound, next_round, estimative[next_round], nil)
					if err != nil {
						return 0, err
					}

					if d.AsyncCoin {
						go computeCoin(next_round)
					}
				}

			}
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

// Create an array from a set
func setToArray(s map[byte]struct{}) []byte {
	result := make([]byte, 0)
	for k := range s {
		result = append(result, k)
	}
	return result
}

// Transforms a map of arrays into a single array
func flatten[I any](m map[int64][]ABAMsg[I]) []ABAMsg[I] {
	result := make([]ABAMsg[I], 0)
	for _, msgs := range m {
		result = append(result, msgs...)
	}
	return result
}

// Filters messages by value
func filterByValue[I any](msgs []ABAMsg[I], value byte) []ABAMsg[I] {
	result := make([]ABAMsg[I], 0)
	for _, msg := range msgs {
		if msg.Estimative() == value {
			result = append(result, msg)
		}
	}
	return result
}

// Filters messages by round and value
func filterByRoundAndValue[I any](msgs []ABAMsg[I], round int64, value byte) []ABAMsg[I] {
	result := make([]ABAMsg[I], 0)
	for _, msg := range msgs {
		if msg.Round() == round && msg.Estimative() == value {
			result = append(result, msg)
		}
	}
	return result
}

// Filters messages by round and values. Returned messages have an estimative that is in the values array
func filterByRoundAndValues[I any](msgs []ABAMsg[I], round int64, values []byte) []ABAMsg[I] {
	result := make([]ABAMsg[I], 0)
	for _, msg := range msgs {
		if msg.Round() == round {
			for _, value := range values {
				if msg.Estimative() == value {
					result = append(result, msg)
				}
			}
		}
	}
	return result
}

// Filters messages by round and values. Returned messages have a values set that is a subset of values
func filterByRoundAndSubsetValues[I any](msgs []ABAMsg[I], round int64, values map[byte]struct{}) []ABAMsg[I] {
	result := make([]ABAMsg[I], 0)
	for _, msg := range msgs {
		if msg.Round() == round {
			isSubset := true
			for value := range msg.Values() {
				if _, exists := values[value]; !exists {
					isSubset = false
					break
				}
			}
			if isSubset {
				result = append(result, msg)
			}
		}
	}
	return result
}
