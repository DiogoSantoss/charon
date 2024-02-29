package alea

import (
	"context"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/alea/aba"
	"github.com/obolnetwork/charon/core/alea/vcbc"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
)

func New(tcpNode host.Host, sender *p2p.Sender, peers []p2p.Peer, p2pKey *k1.PrivateKey) (*Alea, error) {
	return &Alea{
		tcpNode: tcpNode,
		sender:  sender,
		peers:   peers,
		p2pKey:  p2pKey,
	}, nil
}

// alea or aleabft
type Alea struct {
	tcpNode host.Host
	sender  *p2p.Sender
	peers   []p2p.Peer
	p2pKey  *k1.PrivateKey

	// maybe a instanceIO struct similar to qbft

	subs []func(context.Context, core.Duty, core.UnsignedDataSet) error
}

func (a *Alea) Start(ctx context.Context) {
	// register handler for incoming messages
	/*
		need protocolID
		need to define message types
	*/
	//p2p.RegisterHandler("alea", a.tcpNode, protocolID, func() proto.Message { return new() })
}

func (a *Alea) Subscribe(fn func(ctx context.Context, duty core.Duty, set core.UnsignedDataSet) error) {
	a.subs = append(a.subs, fn)
}

func (a *Alea) Participate(context.Context, core.Duty) error {
	// not needed (?)
	// only called after scheduler
	return nil
}

func (a *Alea) Propose(ctx context.Context, duty core.Duty, data core.UnsignedDataSet) error {
	// called after fetcher
	// do VCBC
	// ABA should also start running "in the background"
	// many ABA instances may run while single VCBC instance is running
	// (this can be optimized, e.g. estimate duration for VCBC to finish and then start aba)
	// (we cant wait for vcbc to finish: why in paper)
	return nil
}

// -------------------------------------------- POC ------------------------

/*

Does it make sense to have a RunAlea method or should we only have RunVCBC and RunABA?

Upon Participate() we could start ABA and upon Propose() we could start VCBC with the duty


*/

func (a *Alea) RunAlea(ctx context.Context, id uint, slot uint, valueChannel chan []byte, pubKey tbls.PublicKey, pubKeys map[uint]tbls.PublicKey, privKey tbls.PrivateKey) error {

	ctx = log.WithTopic(ctx, "alea")

	log.Info(ctx, "Starting Alea", z.Uint("id", id))

	// === State ===
	var (
		vcbcInstance   *vcbc.VCBC = vcbc.NewVCBC()
		agreementRound uint       = 0
		valuePerPeer              = make(map[uint][]byte)
	)

	getLeaderId := func() uint {
		return 0
	}

	broadcastAba := func(aba.ABAMessage) error {
		return nil
	}

	receiveAba := make(chan aba.ABAMessage)

	broadcastCommonCoin := func(aba.CommonCoinMessage) error {
		return nil
	}

	receiveCommonCoin := make(chan aba.CommonCoinMessage)

	broadcastVCBC := func(vcbc.VCBCMessage) error {
		return nil
	}

	unicastVCBC := func(uint, vcbc.VCBCMessage) error {
		return nil
	}

	receiveVCBC := make(chan vcbc.VCBCMessage)

	// Store result of VCBC
	vcbcInstance.Subscribe(func(ctx context.Context, result vcbc.VCBCResult) error {
		valuePerPeer[vcbc.IdFromTag(result.Tag)] = result.Message
		return nil
	})

	{
		/*
			Problem:
			Run and RunRequest should share data

			After RunRequest i have a signature that could help others receive the message
			however it may not be present in Run. therefore when someone asks for the message
			i may not be able to provide them with a signature since its only present on RunRequest data
			and not on Run data


		*/

		// Broadcast component
		go func() {
			for value := range valueChannel {
				err := vcbcInstance.Run(ctx, id, slot, pubKey, pubKeys, privKey, value, broadcastVCBC, unicastVCBC, receiveVCBC)
				valueChannel = nil
				if err != nil {
					// TODO handle error
				}
			}
		}()

		// Agreement component
		go func() {
			for {
				leaderId := getLeaderId()
				value := valuePerPeer[leaderId]
				proposal := byte(0)
				if value != nil {
					proposal = byte(1)
				}
				result, err := aba.RunABA(ctx, id, slot, agreementRound, pubKey, pubKeys, privKey, proposal, broadcastAba, receiveAba, broadcastCommonCoin, receiveCommonCoin)
				if err != nil {
					// TODO: What to do with error?
				}

				if result == 1 {
					value := valuePerPeer[leaderId]
					if value == nil {
						vcbcInstance.BroadcastRequest(ctx, id, vcbc.BuildTag(leaderId, slot), broadcastVCBC)
					}

					// TODO: Wait until valuePerPeer[leaderId] is not nil

					for _, sub := range a.subs {
						sub(ctx, core.Duty{}, core.UnsignedDataSet{})
					}
				}
				agreementRound += 1
			}
		}()
	}

	return nil
}
