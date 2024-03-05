package alea

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/alea/aba"
	"github.com/obolnetwork/charon/core/alea/vcbc"
	"github.com/obolnetwork/charon/tbls"
)

type Alea struct {
	/*
		tcpNode host.Host
		sender  *p2p.Sender
		peers   []p2p.Peer
		p2pKey  *k1.PrivateKey

		subs []func(context.Context, core.Duty, core.UnsignedDataSet) error
	*/

	n    int
	f    int
	subs []func(ctx context.Context, result []byte) error
}

func NewAlea(n int, f int) *Alea {
	return &Alea{
		n: n,
		f: f,
	}
}

func (a *Alea) Start(ctx context.Context) {
	// WIP
	// register handler for incoming messages
	/*
		need protocolID
		need to define message types
	*/
	//p2p.RegisterHandler("alea", a.tcpNode, protocolID, func() proto.Message { return new() })
}

/*
func (a *Alea) Subscribe(fn func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error) {
	a.subs = append(a.subs, fn)
}
*/

func (a *Alea) Participate(context.Context, core.Duty) error {
	// WIP
	return nil
}

func (a *Alea) Propose(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	// WIP
	return nil
}

func (a *Alea) Subscribe(fn func(ctx context.Context, result []byte) error) {
	a.subs = append(a.subs, fn)
}

/*
	How to avoid active wait
	Error (in error.err) concurrent ite and write that should not exist
	How to handle errors inside goroutines ?


	How to use the networking layer instead of hand made channels ?
	How to separate protocol messages so that ,e.g., ABA doesn't try to handle VCBC messages ?
	How to test using peer to peer network ?
*/

func (a *Alea) Run(ctx context.Context, id uint, slot uint, valueChannel chan []byte, pubKey tbls.PublicKey, pubKeys map[uint]tbls.PublicKey, privKey tbls.PrivateKey,
	broadcastAba func(aba.ABAMessage) error, receiveAba chan aba.ABAMessage, broadcastCommonCoin func(aba.CommonCoinMessage) error, receiveCommonCoin chan aba.CommonCoinMessage,
	broadcastVCBC func(vcbc.VCBCMessage) error, unicastVCBC func(uint, vcbc.VCBCMessage) error, receiveVCBC chan vcbc.VCBCMessage) (err error) {

	defer func() {
		// Panics are used for assertions and sanity checks to reduce lines of code
		// and to improve readability. Catch them here.
		if r := recover(); r != nil {
			if !strings.Contains(fmt.Sprint(r), "bug") {
				panic(r) // Only catch internal sanity checks.
			}
			err = fmt.Errorf("alea sanity check: %v", r) //nolint: forbidigo // Wrapping a panic, not error.
		}
	}()

	ctx = log.WithTopic(ctx, "alea")

	log.Info(ctx, "Starting Alea", z.Uint("id", id))

	// === State ===
	var (
		abaInstance       *aba.ABA   = aba.NewABA(a.n, a.f)
		vcbcInstance      *vcbc.VCBC = vcbc.NewVCBC(a.n, a.f)
		agreementRound    uint       = 0
		valuePerPeerMutex sync.Mutex
		valuePerPeer      = make(map[uint][]byte)
	)

	getLeaderId := func() uint {
		return agreementRound%uint(a.n) + 1
	}

	// Store result of VCBC
	vcbcInstance.Subscribe(func(ctx context.Context, result vcbc.VCBCResult) error {
		valuePerPeerMutex.Lock()
		valuePerPeer[vcbc.IdFromTag(result.Tag)] = result.Message
		log.Info(ctx, "Node id has value from source", z.Uint("id", id), z.Uint("slot", slot), z.Uint("source", vcbc.IdFromTag(result.Tag)))
		valuePerPeerMutex.Unlock()
		return nil
	})

	{
		// Broadcast component
		go func() {
			log.Info(ctx, "Starting broadcast component", z.Uint("id", id), z.Uint("slot", slot))
			for value := range valueChannel {
				valueChannel = nil
				log.Info(ctx, "Broadcasting value", z.Uint("id", id), z.Uint("slot", slot))
				err := vcbcInstance.Run(ctx, id, slot, pubKey, pubKeys, privKey, value, broadcastVCBC, unicastVCBC, receiveVCBC)
				if err != nil {
					// TODO how handle error?
				}
			}
		}()

		// Agreement component
		go func() {
			log.Info(ctx, "Starting agreement component", z.Uint("id", id))

			for {
				leaderId := getLeaderId()
				valuePerPeerMutex.Lock()
				value := valuePerPeer[leaderId]
				valuePerPeerMutex.Unlock()
				proposal := byte(0)
				if value != nil {
					proposal = byte(1)
				}
				log.Info(ctx, "Starting agreement round with leader and proposal", z.Uint("id", id), z.Uint("slot", slot), z.Uint("tag", agreementRound), z.Uint("leaderId", leaderId), z.Uint("proposal", uint(proposal)))
				result, err := abaInstance.Run(ctx, id, slot, agreementRound, pubKey, pubKeys, privKey, proposal, broadcastAba, receiveAba, broadcastCommonCoin, receiveCommonCoin)
				log.Info(ctx, "Received result from ABA", z.Uint("id", id), z.Uint("slot", slot), z.Uint("tag", agreementRound), z.Uint("result", uint(result)))
				if err != nil {
					// TODO how handle error?
				}

				if result == 1 {
					valuePerPeerMutex.Lock()
					value := valuePerPeer[leaderId]
					valuePerPeerMutex.Unlock()
					if value == nil {
						log.Info(ctx, "Leader value not found, requesting value", z.Uint("id", id), z.Uint("slot", slot), z.Uint("tag", agreementRound), z.Uint("leaderId", leaderId))
						err = vcbcInstance.BroadcastRequest(ctx, id, vcbc.BuildTag(leaderId, slot), broadcastVCBC)
						if err != nil {
							// TODO how handle error?
						}

						// TODO Should not active wait for the value
						// How ?
						for {
							// Technically, if this has been filled, no one will be writing to it again
							// so no need to lock from here onwards
							if valuePerPeer[leaderId] != nil {
								break
							}
						}
					}

					log.Info(ctx, "Agreement reached", z.Uint("id", id), z.Uint("slot", slot), z.Uint("tag", agreementRound))
					for _, sub := range a.subs {
						sub(ctx, valuePerPeer[leaderId])
					}
					break
				}
				agreementRound += 1
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
