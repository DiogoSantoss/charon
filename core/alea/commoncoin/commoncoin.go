package commoncoin

import (
	"context"
	"math"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
)

// CommonCoin implementation from the paper: "The Honey Badger of BFT Protocols"
// Link: https://eprint.iacr.org/2016/199.pdf (Figure 12)

type Transport[I any] struct {
	Broadcast func(ctx context.Context, msg CommonCoinMessage[I]) error
	Unicast   func(ctx context.Context, target int64, msg CommonCoinMessage[I]) error
	Receive   <-chan CommonCoinMessage[I]
}

type Definition[I any] struct {
	// GetCommonCoinName returns a unique nonce representing the coin name for a given instance, agreement round, and aba round
	GetCommonCoinName func(instance I, agreementRound, abaRound int64) ([]byte, error)
	// GetCommonCoinNameSigned returns a signature share of the coin name
	GetCommonCoinNameSigned func(instance I, agreementRound, abaRound int64) (tbls.Signature, error)
	// GetCommonCoinResult returns the coin result by threshold aggregating the signatures
	GetCommonCoinResult func(ctx context.Context, instance I, agreementRound, abaRound int64, signatures map[int]tbls.Signature) (byte, error)
	// VerifySignature returns an error if the signature is invalid
	VerifySignature func(process int64, data []byte, signature tbls.Signature) error

	Nodes int
}

// Faulty returns the maximum number of faulty nodes supported in the system
func (d Definition[I]) Faulty() int {
	return int(math.Floor(float64(d.Nodes-1) / 3))
}

type CommonCoinMessage[I any] struct {
	Source         int64
	Instance       I    
	AgreementRound int64 // Alea round
	AbaRound       int64 // ABA round
	Sig            tbls.Signature
}

func SampleCoin[I any](ctx context.Context, d Definition[I], t Transport[I], instance I, agreementRound int64, abaRound int64, process int64) (byte, error) {

	ctx = log.WithTopic(ctx, "commoncoin")

	log.Info(ctx, "Node id sampled common coin", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", abaRound))

	// === State ===
	var (
		signatures = make(map[int]tbls.Signature)
	)

	coinName, err := d.GetCommonCoinName(instance, agreementRound, abaRound)
	if err != nil {
		return 0, err
	}

	{
		signature, err := d.GetCommonCoinNameSigned(instance, agreementRound, abaRound)
		if err != nil {
			return 0, err
		}

		err = t.Broadcast(ctx, CommonCoinMessage[I]{
			Source:         process,
			Instance:       instance,
			AgreementRound: agreementRound,
			AbaRound:       abaRound,
			Sig:            signature,
		})
		if err != nil {
			return 0, err
		}
	}

	for {
		select {
		case msg := <-t.Receive:

			// ignore messages from other rounds
			if msg.AgreementRound != agreementRound || msg.AbaRound != abaRound {
				continue
			}

			// verify signature validity
			err := d.VerifySignature(msg.Source, coinName, msg.Sig)
			if err != nil {
				log.Info(ctx, "Node id received invalid signature from source", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", abaRound), z.I64("source", msg.Source))
				continue
			}

			signatures[int(msg.Source)] = msg.Sig

			if len(signatures) >= int(d.Faulty()+1) {

				result, err := d.GetCommonCoinResult(ctx, instance, agreementRound, abaRound, signatures)
				if err != nil {
					continue
				}

				log.Info(ctx, "Node id decided value", z.I64("id", process), z.I64("agreementRound", agreementRound), z.I64("abaRound", abaRound), z.U8("coin", result))

				return result, nil
			}
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}
