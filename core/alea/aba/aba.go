package aba

import (
	"context"
	"fmt"
	"strings"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
)

// Asynchronous Binary Agreement implementation from the paper: "Cobalt: BFT Governance in Open Networks"
// Link: https://arxiv.org/pdf/1802.07240.pdf (Page 19/20)

type MsgType uint

const (
	MsgUnknown MsgType = iota
	MsgInit
	MsgAux
	MsgConf
	MsgFinish
)

var typeLabels = map[MsgType]string{
	MsgUnknown: "unknown",
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
	UponSupportAux
	UponSupportConf
	UponWeakSupportFinish
	UponStrongSupportFinish
)

var ruleLabels = map[UponRule]string{
	UponNothing:             "nothing",
	UponWeakSupportInit:     "weak_support_init",
	UponStrongSupportInit:   "strong_support_init",
	UponSupportAux:          "support_aux",
	UponSupportConf:         "support_conf",
	UponWeakSupportFinish:   "weak_support_finish",
	UponStrongSupportFinish: "strong_support_finish",
}

func (r UponRule) String() string {
	return ruleLabels[r]
}

type ABAMessage struct {
	MsgType    MsgType
	Source     uint
	Slot       uint
	Tag        uint
	Round      uint
	Estimative byte
	Values     map[byte]struct{}
}

// Returns the triggered upon rule by the received message
func classify(a *ABA, tag uint, msg ABAMessage, values map[byte]struct{}, receivedInit map[uint][]ABAMessage, receivedAux map[uint][]ABAMessage, receivedConf map[uint][]ABAMessage, receivedFinish map[uint][]ABAMessage) UponRule {

	// ignore messages from other slots or tags
	if msg.Slot != a.Slot || msg.Tag != tag {
		return UponNothing
	}

	switch msg.MsgType {
	case MsgInit:
		inits := filterByRoundAndValue(flatten(receivedInit), msg.Round, msg.Estimative)
		if len(inits) >= a.BigQuorum {
			return UponStrongSupportInit
		} else if len(inits) >= a.SmallQuorum {
			return UponWeakSupportInit
		}
	case MsgAux:
		auxs := filterByRoundAndValues(flatten(receivedAux), msg.Round, setToArray(values))
		if len(auxs) >= a.CorrectNodes {
			return UponSupportAux
		}
	case MsgConf:
		confs := filterByRoundAndSubsetValues(flatten(receivedConf), msg.Round, values)
		if len(confs) >= a.CorrectNodes {
			return UponSupportConf
		}
	case MsgFinish:
		finishes := filterByValue(flatten(receivedFinish), msg.Estimative)
		if len(finishes) >= a.BigQuorum {
			return UponStrongSupportFinish
		} else if len(finishes) >= a.SmallQuorum {
			return UponWeakSupportFinish
		}
	default:
		panic("bug: invalid message type")
	}

	return UponNothing
}

type ABA struct {
	// Immutable values
	N       int
	F       int
	Id      uint
	Slot    uint // PoS slot
	PubKey  tbls.PublicKey
	PubKeys map[uint]tbls.PublicKey
	PrivKey tbls.PrivateKey
	// Computed values
	BigQuorum    int
	SmallQuorum  int
	CorrectNodes int
}

func NewABA(n int, f int, id uint, slot uint, pubKey tbls.PublicKey, pubKeys map[uint]tbls.PublicKey, privKey tbls.PrivateKey) *ABA {
	return &ABA{
		N:       n,
		F:       f,
		Id:      id,
		Slot:    slot,
		PubKey:  pubKey,
		PubKeys: pubKeys,
		PrivKey: privKey,

		BigQuorum:    2*f + 1,
		SmallQuorum:  f + 1,
		CorrectNodes: n - f,
	}
}

func (a *ABA) Run(ctx context.Context, tag uint, valueInput byte, broadcast func(ABAMessage) error, receiveChannel <-chan ABAMessage,
	broadcastCommonCoin func(CommonCoinMessage) error, receiveChannelCommonCoin <-chan CommonCoinMessage) (result byte, err error) {

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

	log.Info(ctx, "Starting ABA", z.Uint("id", a.Id))

	// === State ===
	var (
		estimative                    = make(map[uint]byte)
		values                        = make(map[uint]map[byte]struct{})
		coinResult                    = make(map[uint]byte)
		alreadyBroadcastedInit        = make(map[uint]bool)
		alreadyBroadcastedAux         = make(map[uint]bool)
		alreadyBroadcastedFinish bool = false
		receivedInit                  = make(map[uint][]ABAMessage)
		receivedAux                   = make(map[uint][]ABAMessage)
		receivedConf                  = make(map[uint][]ABAMessage)
		receivedFinish                = make(map[uint][]ABAMessage)
	)

	storeMessage := func(msg ABAMessage) {
		switch msg.MsgType {
		case MsgInit:
			receivedInit[msg.Source] = append(receivedInit[msg.Source], msg)
		case MsgAux:
			receivedAux[msg.Source] = append(receivedAux[msg.Source], msg)
		case MsgConf:
			receivedConf[msg.Source] = append(receivedConf[msg.Source], msg)
		case MsgFinish:
			receivedFinish[msg.Source] = append(receivedFinish[msg.Source], msg)
		default:
			panic("bug: invalid message type")
		}
	}

	alreadyBroadcastedInit[0] = true
	values[0] = make(map[byte]struct{})

	// === Algorithm ===
	estimative[0] = valueInput // Algorithm 1:3

	{ // Algorithm 1:4
		err := broadcast(ABAMessage{
			MsgType:    MsgInit,
			Source:     a.Id,
			Slot:       a.Slot,
			Tag:        tag,
			Round:      0,
			Estimative: estimative[0],
		})
		if err != nil {
			return 0, err
		}
	}

	for {
		select {
		case msg := <-receiveChannel:

			// TODO: verify message validity
			storeMessage(msg)

			rule := classify(a, tag, msg, values[msg.Round], receivedInit, receivedAux, receivedConf, receivedFinish)
			if rule == UponNothing {
				break
			}

			switch rule {
			case UponWeakSupportFinish: // Algorithm 1:1
				if !alreadyBroadcastedFinish {
					alreadyBroadcastedFinish = true
					msg.Source = a.Id
					err := broadcast(msg)
					if err != nil {
						return 0, err
					}
				}

			case UponStrongSupportFinish: // Algorithm 1:2
				log.Info(ctx, "Node id decided value", z.Uint("id", a.Id), z.Uint("slot", msg.Slot), z.Uint("tag", msg.Tag), z.Uint("r", msg.Round), z.U8("value", msg.Estimative))
				return msg.Estimative, nil

			case UponWeakSupportInit: // Algorithm 1:5
				msg.Source = a.Id
				err := broadcast(msg)
				if err != nil {
					return 0, err
				}

			case UponStrongSupportInit: // Algorithm 1:6
				if values[msg.Round] == nil {
					values[msg.Round] = make(map[byte]struct{})
				}
				values[msg.Round][msg.Estimative] = struct{}{}
				if !alreadyBroadcastedAux[msg.Round] {
					alreadyBroadcastedAux[msg.Round] = true
					err := broadcast(ABAMessage{
						MsgType:    MsgAux,
						Source:     a.Id,
						Slot:       a.Slot,
						Tag:        tag,
						Round:      msg.Round,
						Estimative: msg.Estimative,
					})
					if err != nil {
						return 0, err
					}
				}

			case UponSupportAux: // Algorithm 1:7
				// Why does this solve the data race??
				// sending values[msg.Round] should be a copy, not the
				// same reference
				values_copy := make(map[byte]struct{})
				for k, v := range values[msg.Round] {
					values_copy[k] = v
				}
				err := broadcast(ABAMessage{
					MsgType: MsgConf,
					Source:  a.Id,
					Slot:    a.Slot,
					Tag:     tag,
					Round:   msg.Round,
					//Values:  values[msg.Round],
					Values: values_copy,
				})
				if err != nil {
					return 0, err
				}

			case UponSupportConf: // Algorithm 1:8

				sr, exists := coinResult[msg.Round]
				if !exists {
					c := NewCommonCoin(uint(a.F), a.Id, a.Slot, tag, msg.Round, a.PubKey, a.PubKeys, a.PrivKey)
					coinValue, err := c.SampleCoin(ctx, broadcastCommonCoin, receiveChannelCommonCoin) // Algorithm 1:9
					if err != nil {
						return 0, err
					}
					sr = coinValue
					coinResult[msg.Round] = coinValue
				}

				//Algorithm 1:10
				if len(values[msg.Round]) == 2 {
					estimative[msg.Round+1] = sr
					log.Info(ctx, "Node id has two values", z.Uint("id", a.Id), z.Uint("slot", msg.Slot), z.Uint("tag", msg.Tag), z.Uint("r", msg.Round))

				} else if len(values[msg.Round]) == 1 {
					var value byte
					for k := range values[msg.Round] {
						value = k
					}

					estimative[msg.Round+1] = value

					if (value == sr) && (!alreadyBroadcastedFinish) {
						log.Info(ctx, "Node id has value matching with coin", z.Uint("id", a.Id), z.Uint("slot", msg.Slot), z.Uint("tag", msg.Tag), z.Uint("r", msg.Round), z.U8("value", value))
						alreadyBroadcastedFinish = true
						err := broadcast(ABAMessage{
							MsgType:    MsgFinish,
							Source:     a.Id,
							Slot:       a.Slot,
							Tag:        tag,
							Round:      msg.Round,
							Estimative: sr,
						})
						if err != nil {
							return 0, err
						}
					} else if (value != sr) && (!alreadyBroadcastedFinish) {
						log.Info(ctx, "Node id has value not matching with coin", z.Uint("id", a.Id), z.Uint("slot", msg.Slot), z.Uint("tag", msg.Tag), z.Uint("r", msg.Round), z.U8("value", value), z.U8("coin", sr))
					}
				}

				// Equivalent to "return to step 4" in Algorithm 1:10
				next_round := msg.Round + 1

				if !alreadyBroadcastedInit[next_round] {

					alreadyBroadcastedInit[next_round] = true
					if values[next_round] == nil {
						values[next_round] = make(map[byte]struct{})
					}

					log.Info(ctx, "Node id starting new round", z.Uint("id", a.Id), z.Uint("slot", msg.Slot), z.Uint("tag", msg.Tag), z.Uint("r", next_round))
					err := broadcast(ABAMessage{
						MsgType:    MsgInit,
						Source:     a.Id,
						Slot:       a.Slot,
						Tag:        tag,
						Round:      next_round,
						Estimative: estimative[next_round],
					})
					if err != nil {
						return 0, err
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
func flatten(m map[uint][]ABAMessage) []ABAMessage {
	result := make([]ABAMessage, 0)
	for _, msgs := range m {
		result = append(result, msgs...)
	}
	return result
}

// Filters messages by value
func filterByValue(msgs []ABAMessage, value byte) []ABAMessage {
	result := make([]ABAMessage, 0)
	for _, msg := range msgs {
		if msg.Estimative == value {
			result = append(result, msg)
		}
	}
	return result
}

// Filters messages by round and value
func filterByRoundAndValue(msgs []ABAMessage, round uint, value byte) []ABAMessage {
	result := make([]ABAMessage, 0)
	for _, msg := range msgs {
		if msg.Round == round && msg.Estimative == value {
			result = append(result, msg)
		}
	}
	return result
}

// Filters messages by round and values. Returned messages have an estimative that is in the values array
func filterByRoundAndValues(msgs []ABAMessage, round uint, values []byte) []ABAMessage {
	result := make([]ABAMessage, 0)
	for _, msg := range msgs {
		if msg.Round == round {
			for _, value := range values {
				if msg.Estimative == value {
					result = append(result, msg)
				}
			}
		}
	}
	return result
}

// Filters messages by round and values. Returned messages have a values set that is a subset of values
func filterByRoundAndSubsetValues(msgs []ABAMessage, round uint, values map[byte]struct{}) []ABAMessage {
	result := make([]ABAMessage, 0)
	for _, msg := range msgs {
		if msg.Round == round {
			isSubset := true
			for value := range msg.Values {
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
