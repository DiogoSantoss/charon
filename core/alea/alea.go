package alea

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/alea/aba"
	"github.com/obolnetwork/charon/core/alea/commoncoin"
	"github.com/obolnetwork/charon/core/alea/vcbc"
)

type Definition[I any, V comparable] struct {
	GetLeader func(instance I, agreementRound int64) int64
	Decide    func(ctx context.Context, instance I, result V)

	DelayABA bool
	Nodes    int
}

func Run[I any, V comparable](
	ctx context.Context,
	d Definition[I, V],
	dVCBC vcbc.Definition[I, V], tVCBC vcbc.Transport[I, V],
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
		// Current agreement round
		agreementRound    int64 = 0

		// Received value per peer from VCBC
		valuePerPeer            = make(map[int64]V)
		// Channel to signal when a new value is received
		valuePerPeerCh          = make(chan struct{})
		// Mutex to protect valuePerPeer and valuePerPeerCh
		valuePerPeerMutex sync.Mutex

		// Error channel to receive errors from broadcast and agreement components
		errCh             = make(chan error)
	)

	// Results from VCBC are stored in a peer id indexed map
	// We use a channel to signal when a new value is received 
	dVCBC.Subs = append(dVCBC.Subs, func(ctx context.Context, result vcbc.VCBCResult[V]) error {
		valuePerPeerMutex.Lock()
		defer valuePerPeerMutex.Unlock()

		valuePerPeer[dVCBC.IdFromTag(result.Tag)] = result.Result
		if process == dVCBC.IdFromTag(result.Tag) {
			core.RecordStep(process-1, core.FINISH_VCBC)
		}

		// Reference: https://gist.github.com/creachadair/ed1ebebc7df66d19ad7100e8f9296d0a
		close(valuePerPeerCh)
		valuePerPeerCh = make(chan struct{})

		return nil
	})

	{
		// Broadcast component
		go func() {
			for value := range inputValueCh {
				// Close channel since only one value is expected per consensus instance
				inputValueCh = nil
				core.RecordStep(process-1, core.START_VCBC)
				// In theory, should run forever to ensure all nodes can receive all values
				// In practice, we run until context is done or an error occurs
				err := vcbc.Run(ctx, dVCBC, tVCBC, instance, process, value)
				if err != nil {
					errCh <- err
					log.Info(ctx, "Error in broadcast component", z.I64("id", process), z.Err(err))
					return
				}
			}
		}()

		// Agreement component
		go func() {
			// Optimization 3
			if d.DelayABA {
				core.RecordStep(process-1, core.START_DELAY_ABA)

				// Compute number of VCBC values we will wait for before starting ABA
				// With 3f+1 nodes, we can only wait for a maximum of 2f+1 values
				thresholdValueReached := false
				n, f := float64(d.Nodes), math.Floor(float64(d.Nodes-1)/3)
				// This is maximum we can wait for (equivalent to 2f+1 if n=3f+1)
				threshold := int(math.Floor((n+f)/2) + 1)
				// This is another option, wait for less may be faster
				//threshold = int(f + 1)
				
				valuePerPeerMutex.Lock()
				ch := valuePerPeerCh
				valuePerPeerMutex.Unlock()
				
				// Wait for threshold number of values to be received
				for !thresholdValueReached {
					select {
					case <-ctx.Done():
						return
					case <-ch:
						valuePerPeerMutex.Lock()
						ch = valuePerPeerCh
						if len(valuePerPeer) >= threshold {
							thresholdValueReached = true
							log.Info(ctx, "Alea recevied threshold values of VCBCs", z.I64("id", process))
						}
						valuePerPeerMutex.Unlock()
					}
				}
				core.RecordStep(process-1, core.FINISH_DELAY_ABA)
			}
			core.RecordStep(process-1, core.START_ABA)
			for {
				leaderId := d.GetLeader(instance, agreementRound)

				valuePerPeerMutex.Lock()
				_, exists := valuePerPeer[leaderId]
				valuePerPeerMutex.Unlock()

				proposal := byte(0)
				if exists {
					proposal = byte(1)
				}

				result, err := aba.Run(ctx, dABA, tABA, dCoin, tCoin, instance, process, agreementRound, proposal)

				if err != nil {
					errCh <- err
					log.Info(ctx, "Error in agreement component (ABA)", z.I64("id", process), z.Err(err))
					return
				}
				log.Info(ctx, "Alea result from ABA", z.I64("id", process), z.I64("agreementRound", agreementRound), z.Uint("result", uint(result)))

				if result == 1 {
					valuePerPeerMutex.Lock()
					value, exists := valuePerPeer[leaderId]
					ch := valuePerPeerCh
					valuePerPeerMutex.Unlock()

					core.RecordStep(process-1, core.START_VCBC_REQUEST)
					if !exists {
						log.Info(ctx, "Alea empty leader value", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("leaderId", leaderId))
						err = vcbc.BroadcastRequest(ctx, dVCBC, tVCBC, instance, process, dVCBC.BuildTag(instance, leaderId))
						if err != nil {
							errCh <- err
							log.Info(ctx, "Error in agreement component (VCBC request)", z.I64("id", process), z.Err(err))
							return
						}

						for !exists {
							select {
							case <-ctx.Done():
								log.Info(ctx, "Context done, did not decide", z.I64("id", process), z.I64("agreementRound", agreementRound))
								return
							case <-ch:
								valuePerPeerMutex.Lock()
								value, exists = valuePerPeer[leaderId]
								ch = valuePerPeerCh
								valuePerPeerMutex.Unlock()
							}
						}
					}
					core.RecordStep(process-1, core.FINISH_VCBC_REQUEST)

					log.Info(ctx, "Alea decided", z.I64("id", process), z.I64("agreementRound", agreementRound))
					core.RecordStep(process-1, core.FINISH_ABA)
					core.RecordStep(process-1, core.START_DECIDE)
					d.Decide(ctx, instance, value)
					core.RecordStep(process-1, core.FINISH_DECIDE)
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
		case err := <-errCh:
			return err
		}
	}
}
