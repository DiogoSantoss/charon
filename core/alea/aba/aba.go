package aba

import (
	"context"

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
	Estimative uint
	Values     map[uint]struct{}
	Round      uint
}

// Returns the triggered upon rule by the received message
func classify(msg ABAMessage, values map[uint]struct{}, receivedInit map[uint][]ABAMessage, receivedAux map[uint][]ABAMessage, receivedConf map[uint][]ABAMessage, receivedFinish map[uint][]ABAMessage) UponRule {

	// TODO: get these consts from somewhere
	f := 1
	n := 3*f + 1
	smallQuorum := f + 1
	bigQuorum := 2*f + 1

	switch msg.MsgType {
	case MsgInit:
		inits := filterByRoundAndValue(flatten(receivedInit), msg.Round, msg.Estimative)
		if len(inits) >= bigQuorum {
			return UponStrongSupportInit
		} else if len(inits) >= smallQuorum {
			return UponWeakSupportInit
		}
	case MsgAux:
		auxs := filterByRoundAndValues(flatten(receivedAux), msg.Round, setToArray(values))
		if len(auxs) >= n-f {
			return UponSupportAux
		}
	case MsgConf:
		confs := filterByRoundAndSubsetValues(flatten(receivedConf), msg.Round, values)
		if len(confs) >= n-f {
			return UponSupportConf
		}
	case MsgFinish:
		finishes := filterByValue(flatten(receivedFinish), msg.Estimative)
		if len(finishes) >= bigQuorum {
			return UponStrongSupportFinish
		} else if len(finishes) >= smallQuorum {
			return UponWeakSupportFinish
		}
	default:
		panic("bug: invalid message type")
	}

	return UponNothing
}

func RunABA(ctx context.Context, id uint, slot uint, pubKey tbls.PublicKey, pubKeys map[uint]tbls.PublicKey, privKey tbls.PrivateKey, valueInput uint, broadcast func(ABAMessage) error, receiveChannel <-chan ABAMessage,
	broadcastCommonCoin func(CommonCoinMessage) error, receiveChannelCommonCoin <-chan CommonCoinMessage) (uint, error) {

	ctx = log.WithTopic(ctx, "aba")

	log.Info(ctx, "Node id starting ABA", z.Uint("id", id))

	// === State ===
	var (
		round                    uint = 0
		estimative                    = make(map[uint]uint)
		values                        = make(map[uint]map[uint]struct{})
		coinResult                    = make(map[uint]uint)
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
			receivedConf[msg.Source] = append(receivedAux[msg.Source], msg)
		case MsgFinish:
			receivedFinish[msg.Source] = append(receivedFinish[msg.Source], msg)
		default:
			panic("bug: invalid message type")
		}
	}

	alreadyBroadcastedInit[round] = true
	values[round] = make(map[uint]struct{})

	// === Algorithm ===
	estimative[round] = valueInput // Algorithm 1:3

	{ // Algorithm 1:4
		err := broadcast(ABAMessage{
			MsgType:    MsgInit,
			Source:     id,
			Estimative: estimative[round],
			Round:      round,
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

			rule := classify(msg, values[msg.Round], receivedInit, receivedAux, receivedConf, receivedFinish)
			if rule == UponNothing {
				break
			}

			switch rule {
			case UponWeakSupportFinish: // Algorithm 1:1
				if alreadyBroadcastedFinish == false {
					alreadyBroadcastedFinish = true
					msg.Source = id
					err := broadcast(msg)
					if err != nil {
						return 0, err
					}
				}

			case UponStrongSupportFinish: // Algorithm 1:2
				log.Info(ctx, "Node id in round r decided value", z.Uint("id", id), z.Uint("r", msg.Round), z.Uint("value", msg.Estimative))
				return msg.Estimative, nil

			case UponWeakSupportInit: // Algorithm 1:5
				msg.Source = id
				err := broadcast(msg)
				if err != nil {
					return 0, err
				}

			case UponStrongSupportInit: // Algorithm 1:6
				values[msg.Round][msg.Estimative] = struct{}{}
				if alreadyBroadcastedAux[msg.Round] == false {
					alreadyBroadcastedAux[msg.Round] = true
					err := broadcast(ABAMessage{
						MsgType:    MsgAux,
						Source:     id,
						Estimative: msg.Estimative,
						Round:      msg.Round,
					})
					if err != nil {
						return 0, err
					}
				}

			case UponSupportAux: // Algorithm 1:7
				err := broadcast(ABAMessage{
					MsgType: MsgConf,
					Source:  id,
					Values:  values[msg.Round],
					Round:   msg.Round,
				})
				if err != nil {
					return 0, err
				}

			case UponSupportConf: // Algorithm 1:8

				sr, exists := coinResult[msg.Round]
				if !exists {
					coinValue, err := SampleCoin(ctx, id, slot, msg.Round, pubKey, pubKeys, privKey, broadcastCommonCoin, receiveChannelCommonCoin) // Algorithm 1:9
					if err != nil {
						return 0, err
					}
					sr = coinValue
					coinResult[msg.Round] = coinValue
				}

				//Algorithm 1:10
				if len(values[msg.Round]) == 2 {
					estimative[msg.Round+1] = sr
					log.Info(ctx, "Node id in round r has two values", z.Uint("id", id), z.Uint("r", msg.Round))

				} else if len(values[msg.Round]) == 1 {
					var value uint
					for k := range values[msg.Round] {
						value = k
					}

					estimative[msg.Round+1] = value

					if (value == sr) && (alreadyBroadcastedFinish == false) {
						log.Info(ctx, "Node id in round r has value matching with coin", z.Uint("id", id), z.Uint("r", msg.Round), z.Uint("value", value), z.Uint("coin", sr))
						alreadyBroadcastedFinish = true
						err := broadcast(ABAMessage{
							MsgType:    MsgFinish,
							Source:     id,
							Estimative: sr,
							Round:      msg.Round,
						})
						if err != nil {
							return 0, err
						}
					}
				}

				// Equivalent to "return to step 4" in Algorithm 1:10
				next_round := msg.Round + 1

				if alreadyBroadcastedInit[next_round] == false {

					// TODO: I am not sure of this "round += 1"
					/*
						we may be round 1
						receive a message from round 3
						should we skip round 2 and 3? i dont think so
						maybe send init for round 3+1
						but locally go to round 2

						not sure, algorithm does not say

						maybe this example is not even possible, need to
						check more carefully
					*/
					round += 1

					alreadyBroadcastedInit[next_round] = true
					values[next_round] = make(map[uint]struct{})

					log.Info(ctx, "Node id starting new round", z.Uint("id", id), z.Uint("round", round))
					err := broadcast(ABAMessage{
						MsgType:    MsgInit,
						Source:     id,
						Estimative: estimative[round],
						Round:      next_round,
					})
					if err != nil {
						return 0, err
					}
				}

			}
		}
	}
}

// Create an array from a set
func setToArray(s map[uint]struct{}) []uint {
	result := make([]uint, 0)
	for k := range s {
		result = append(result, k)
	}
	return result
}

// Transforms a map of arrays into a single array
func flatten(m map[uint][]ABAMessage) []ABAMessage {
	result := make([]ABAMessage, 0)
	for _, msgs := range m {
		for _, msg := range msgs {
			result = append(result, msg)
		}
	}
	return result
}

// Filters messages by round
func filterByRound(msgs []ABAMessage, round uint) []ABAMessage {
	result := make([]ABAMessage, 0)
	for _, msg := range msgs {
		if msg.Round == round {
			result = append(result, msg)
		}
	}
	return result
}

func filterByValue(msgs []ABAMessage, value uint) []ABAMessage {
	result := make([]ABAMessage, 0)
	for _, msg := range msgs {
		if msg.Estimative == value {
			result = append(result, msg)
		}
	}
	return result
}

// Filters messages by round and value
func filterByRoundAndValue(msgs []ABAMessage, round uint, value uint) []ABAMessage {
	result := make([]ABAMessage, 0)
	for _, msg := range msgs {
		if msg.Round == round && msg.Estimative == value {
			result = append(result, msg)
		}
	}
	return result
}

// Filters messages by round and values. Returned messages have an estimative that is in the values array
func filterByRoundAndValues(msgs []ABAMessage, round uint, values []uint) []ABAMessage {
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
func filterByRoundAndSubsetValues(msgs []ABAMessage, round uint, values map[uint]struct{}) []ABAMessage {
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
