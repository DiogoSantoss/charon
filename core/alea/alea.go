package alea

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core/alea/aba"
	"github.com/obolnetwork/charon/core/alea/commoncoin"
	"github.com/obolnetwork/charon/core/alea/vcbc"
	"github.com/obolnetwork/charon/tbls"
)

type Definition[I any, V comparable] struct {
	GetLeader func(instance I, agreementRound int64) int64
	SignData  func(data []byte) (tbls.Signature, error)
	Output    func(ctx context.Context, result V) error

	Nodes int
}

/*
	Questions:

	How to avoid active wait
	Error (in error.err) concurrent ite and write that should not exist
	How to handle errors inside goroutines ?

	How to use the networking layer instead of hand made channels ?
	How to separate protocol messages so that ,e.g., ABA doesn't try to handle VCBC messages ?
		anything to do with p2p.RegisterHandler ?
	How to test using peer to peer network ?

    Why do we need [I any, V comparable] ?
		I is for instance (used as Core.Duty to identify a unique consensu instance)
		V is for the value being agreed upon

		Should instance have more parameters in this case ? (agreementRound, abaRound, etc) ?

		How to log with this generic instance ?
			Can pass message logs using definition


*/

func Run[I any, V comparable](
	ctx context.Context,
	d Definition[I, V],
	dVCBC vcbc.Definition[I, V], tVCBC vcbc.Transport[V],
	dABA aba.Definition, tABA aba.Transport[I],
	dCoin commoncoin.Definition[I], tCoin commoncoin.Transport[I],
	instance I, process int64, inputValueCh <-chan V,
) (err error) {

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

	log.Info(ctx, "Starting Alea", z.I64("id", process))

	// === State ===
	var (
		agreementRound    int64 = 0
		valuePerPeerMutex sync.Mutex
		valuePerPeer      = make(map[int64]V)
	)

	// TODO is this ok ? we are creating the vcbc definition outside but defining output inside
	// We could also have a subscriber pattern but alea is the only one that uses vcbc output
	dVCBC.Output = func(ctx context.Context, result vcbc.VCBCResult[V]) error {
		valuePerPeerMutex.Lock()
		defer valuePerPeerMutex.Unlock()

		valuePerPeer[dVCBC.IdFromTag(result.Tag)] = result.Result

		log.Info(ctx, "Node id has value from source", z.I64("id", process), z.I64("source", dVCBC.IdFromTag(result.Tag)))
		return nil
	}

	{
		// Broadcast component
		go func() {
			log.Info(ctx, "Starting broadcast component", z.I64("id", process))
			for value := range inputValueCh {
				// Close channel since only one value is expected per consensus instance
				inputValueCh = nil
				log.Info(ctx, "Broadcasting value", z.I64("id", process))
				err := vcbc.Run[I, V](ctx, dVCBC, tVCBC, instance, process, value)
				if err != nil {
					// TODO how handle error?
				}
			}
		}()

		// Agreement component
		go func() {
			log.Info(ctx, "Starting agreement component", z.I64("id", process))

			for {
				leaderId := d.GetLeader(instance, agreementRound)

				valuePerPeerMutex.Lock()
				_, exists := valuePerPeer[leaderId]
				valuePerPeerMutex.Unlock()

				proposal := byte(0)
				if exists {
					proposal = byte(1)
				}

				log.Info(ctx, "Starting agreement round with leader and proposal", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("leaderId", leaderId), z.Uint("proposal", uint(proposal)))

				result, err := aba.Run(ctx, dABA, tABA, dCoin, tCoin, instance, process, agreementRound, proposal)

				log.Info(ctx, "Received result from ABA", z.I64("id", process), z.I64("agreementRound", agreementRound), z.Uint("result", uint(result)))
				if err != nil {
					// TODO how handle error?
				}

				if result == 1 {
					valuePerPeerMutex.Lock()
					value, exists := valuePerPeer[leaderId]
					valuePerPeerMutex.Unlock()

					if !exists {
						log.Info(ctx, "Leader value not found, requesting value", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("leaderId", leaderId))
						err = vcbc.BroadcastRequest(ctx, dVCBC, tVCBC, instance, process, dVCBC.BuildTag(instance, process))
						if err != nil {
							// TODO how handle error?
						}

						// TODO Should not active wait for the value
						// How ?
						for {
							if value, exists = valuePerPeer[leaderId]; exists {
								break
							}
						}
					}

					log.Info(ctx, "Agreement reached", z.I64("id", process), z.I64("agreementRound", agreementRound))
					d.Output(ctx, value)
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
