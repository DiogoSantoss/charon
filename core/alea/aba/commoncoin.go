package aba

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
)

// CommonCoin implementation from the paper: "The Honey Badger of BFT Protocols"
// Link: https://eprint.iacr.org/2016/199.pdf (Figure 12)

type CommonCoinMessage struct {
	Source uint
	Slot   uint
	Round  uint
	Sig    tbls.Signature
}

// GetCommonCoinName returns a unique nonce representing the coin name
// for the given slot and round
func getCommonCoinName(slot uint, round uint) ([]byte, error) {
	name := fmt.Sprintf("AleaCommmonCoin%v%v", slot, round)
	nonce := sha256.Sum256([]byte(name))

	return nonce[:], nil
}

// GetCommonCoinNameSigned returns a signature share of the coin name
func getCommonCoinNameSigned(slot uint, round uint, privateKey tbls.PrivateKey) (tbls.Signature, error) {
	name, err := getCommonCoinName(slot, round)
	if err != nil {
		return tbls.Signature{}, err
	}

	return tbls.Sign(privateKey, name)
}

// GetCommonCoinResult returns the coin result by threshold aggregating the signatures
func getCommonCoinResult(ctx context.Context, slot uint, round uint, pubKey tbls.PublicKey, signatures map[int]tbls.Signature) (uint, error) {
	totalSig, err := tbls.ThresholdAggregate(signatures)
	if err != nil {
		return 0, err
	}

	sid, err := getCommonCoinName(slot, round)
	if err != nil {
		return 0, err
	}

	err = tbls.Verify(pubKey, sid, totalSig)
	if err != nil {
		log.Info(ctx, "Failed to verify aggregate signature")
		return 0, err
	}

	return uint(totalSig[0] & 1), nil
}

func SampleCoin(ctx context.Context, id uint, slot uint, round uint, pubKey tbls.PublicKey, pubKeys map[uint]tbls.PublicKey,
	privKey tbls.PrivateKey, broadcast func(CommonCoinMessage) error, receiveChannel <-chan CommonCoinMessage) (uint, error) {

	log.Info(ctx, "Node id sampled common coin", z.Uint("id", id))

	// === State ===
	var (
		f          uint = 1 // should get F from somewhere, e.g. GetSmallQuorumSize()
		signatures      = make(map[int]tbls.Signature)
	)

	coinName, err := getCommonCoinName(slot, round)
	if err != nil {
		return 0, err
	}

	{
		signature, err := getCommonCoinNameSigned(slot, round, privKey)
		if err != nil {
			return 0, err
		}
		signatures[int(id)] = signature
		err = broadcast(CommonCoinMessage{
			Source: uint(id),
			Slot:   uint(slot),
			Round:  uint(round),
			Sig:    signature,
		})
		if err != nil {
			return 0, err
		}
	}

	for {
		select {
		case msg := <-receiveChannel:

			log.Info(ctx, "Node id received signature from source", z.Uint("id", id), z.Uint("source", msg.Source))

			// verify signature validity
			err := tbls.Verify(pubKeys[msg.Source], coinName, msg.Sig)
			if err != nil {
				log.Info(ctx, "Node id received invalid signature from source", z.Uint("id", id), z.Uint("source", msg.Source))
				continue
			}

			signatures[int(msg.Source)] = msg.Sig

			if len(signatures) >= int(f)+1 {

				result, err := getCommonCoinResult(ctx, slot, round, pubKey, signatures)
				if err != nil {
					continue
				}

				log.Info(ctx, "Node id decided value", z.Uint("id", id), z.Uint("value", result))

				return result, nil
			}
		}
	}
}
