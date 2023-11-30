package aba

import (
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
	msgType    MsgType
	source     uint
	estimative uint
	values     []uint
	round      uint
}

const (
	UponNothing UponRule = iota
	UponWeakSupportInit
	UponStrongSupportInit
	UponSupportAux
	UponSupportConf
	UponWeakSupportFinish
	UponStrongSupportFinish
)

func classify(msg ABAMessage, receivedInit []ABAMessage, receivedAux []ABAMessage, receivedConf []ABAMessage, receivedFinish []ABAMessage) UponRule {

	// TODO: get f from somewhere
	f := 1
	n := 3*f + 1
	smallQuorum := 2*f + 1
	bigQuorum := f + 1

	switch msg.msgType {
	case MsgInit:
		if len(receivedInit) >= bigQuorum {
			return UponStrongSupportInit
		} else if len(receivedInit) >= smallQuorum {
			return UponWeakSupportInit
		}
	case MsgAux:
		if len(receivedAux) >= n-f {
			return UponSupportAux
		}
	case MsgConf:
		if len(receivedConf) >= n-f {
			return UponSupportConf
		}
	case MsgFinish:
		if len(receivedFinish) >= bigQuorum {
			return UponStrongSupportFinish
		} else if len(receivedInit) >= smallQuorum {
			return UponWeakSupportFinish
		}
	}

	return UponNothing
}

func RunABA(id uint, slot uint, privateKey tbls.PrivateKey, valueInput uint, broadcast func(ABAMessage) error, receiveChannel <-chan ABAMessage,
	broadcastCommonCoin func(int, tbls.Signature) error, receiveChannelCommonCoin <-chan TempABAMessage) (uint, error) {

	// === State ===
	var (
		round                    uint = 0
		estimative                    = make(map[uint]uint)
		values                        = make(map[uint][]uint)
		alreadyBroadcastedAux         = make(map[uint]bool)
		alreadyBroadcastedFinish      = make(map[uint]bool)
		receivedInit                  = make(map[uint][]ABAMessage)
		receivedAux                   = make(map[uint][]ABAMessage)
		receivedConf                  = make(map[uint][]ABAMessage)
		receivedFinish                = make(map[uint][]ABAMessage)
	)

	estimative[round] = valueInput

	storeMessage := func(msg ABAMessage) {
		switch msg.msgType {
		case MsgInit:
			receivedInit[msg.source] = append(receivedInit[msg.source], msg)
		case MsgAux:
			receivedAux[msg.source] = append(receivedAux[msg.source], msg)
		case MsgConf:
			receivedConf[msg.source] = append(receivedAux[msg.source], msg)
		case MsgFinish:
			receivedFinish[msg.source] = append(receivedFinish[msg.source], msg)
		default:

		}
	}

	// === Algorithm ===

	{ // Algorithm 1:4
		err := broadcast(ABAMessage{
			msgType:    MsgInit,
			source:     id,
			estimative: estimative[round],
			round:      round,
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

			rule := classify(msg, receivedInit[msg.round], receivedAux[msg.round], receivedConf[msg.round], receivedFinish[msg.round])
			if rule == UponNothing {
				break
			}

			switch rule {

			case UponWeakSupportFinish:
				if alreadyBroadcastedFinish[msg.round] == false {
					alreadyBroadcastedFinish[msg.round] = true
					msg.source = id
					err := broadcast(msg)
					if err != nil {
						return 0, err
					}
				}

			case UponStrongSupportFinish:
				return msg.estimative, nil

			case UponWeakSupportInit: // Algorithm 1:5
				msg.source = id
				err := broadcast(msg)
				if err != nil {
					return 0, err
				}
				// should verify if already broadcast this init message ?

			case UponStrongSupportInit: // Algorithm 1:6
				values[msg.round] = append(values[msg.round], msg.estimative)
				if alreadyBroadcastedAux[msg.round] == false {
					alreadyBroadcastedAux[msg.round] = true
					err := broadcast(ABAMessage{
						msgType:    MsgAux,
						source:     id,
						estimative: msg.estimative,
						round:      msg.round,
					})
					if err != nil {
						return 0, err
					}
				}
			case UponSupportAux: // Algorithm 1:7
				err := broadcast(ABAMessage{
					msgType: MsgConf,
					source:  id,
					values:  values[msg.round],
					round:   msg.round,
				})
				if err != nil {
					return 0, err
				}
			case UponSupportConf: // Algorithm 1:8
				sr, err := SampleCoin(int(id), int(slot), int(msg.round), privateKey, broadcastCommonCoin, receiveChannelCommonCoin) // Algorithm 1:9
				if err != nil {
					return 0, err
				}

				//Algorithm 1:10
				if len(values[msg.round]) == 2 {
					estimative[msg.round+1] = sr
				} else if len(values[msg.round]) == 1 {
					estimative[msg.round+1] = values[msg.round][0]
					if (values[msg.round][0] == sr) && (alreadyBroadcastedFinish[msg.round] == false) {
						alreadyBroadcastedFinish[msg.round] = true
						err := broadcast(ABAMessage{
							msgType:    MsgFinish,
							source:     id,
							estimative: sr,
						})
						if err != nil {
							return 0, err
						}
					}
				}

				// Equivalent to "return to step 4"
				round++
				err = broadcast(ABAMessage{
					msgType:    MsgInit,
					source:     id,
					estimative: estimative[round],
					round:      round,
				})
				if err != nil {
					return 0, err
				}
			}
		}
	}
}
