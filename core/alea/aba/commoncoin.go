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
	Slot   uint // PoS slot
	Tag    uint // ABA instance tag
	Round  uint // ABA round
	Sig    tbls.Signature
}

// GetCommonCoinName returns a unique nonce representing the coin name
// for the given slot and round
func getCommonCoinName(slot uint, tag uint, round uint) ([]byte, error) {
	name := fmt.Sprintf("AleaCommmonCoin%v%v%v", slot, tag, round)
	nonce := sha256.Sum256([]byte(name))

	return nonce[:], nil
}

// GetCommonCoinNameSigned returns a signature share of the coin name
func getCommonCoinNameSigned(slot uint, tag uint, round uint, privateKey tbls.PrivateKey) (tbls.Signature, error) {
	name, err := getCommonCoinName(slot, tag, round)
	if err != nil {
		return tbls.Signature{}, err
	}

	return tbls.Sign(privateKey, name)
}

// GetCommonCoinResult returns the coin result by threshold aggregating the signatures
func getCommonCoinResult(ctx context.Context, slot uint, tag uint, round uint, pubKey tbls.PublicKey, signatures map[int]tbls.Signature) (byte, error) {
	totalSig, err := tbls.ThresholdAggregate(signatures)
	if err != nil {
		return 0, err
	}

	sid, err := getCommonCoinName(slot, tag, round)
	if err != nil {
		return 0, err
	}

	err = tbls.Verify(pubKey, sid, totalSig)
	if err != nil {
		log.Info(ctx, "[COIN] Failed to verify aggregate signature")
		return 0, err
	}

	return totalSig[0] & 1, nil
}

func SampleCoin(ctx context.Context, id uint, slot uint, tag uint, round uint, pubKey tbls.PublicKey, pubKeys map[uint]tbls.PublicKey,
	privKey tbls.PrivateKey, broadcast func(CommonCoinMessage) error, receiveChannel <-chan CommonCoinMessage) (byte, error) {

	ctx = log.WithTopic(ctx, "commoncoin")

	log.Info(ctx, "Node id sampled common coin", z.Uint("id", id), z.Uint("slot", slot), z.Uint("tag", tag), z.Uint("r", round))

	// === State ===
	var (
		f          uint = 1 // should get F from somewhere, e.g. GetSmallQuorumSize()
		signatures      = make(map[int]tbls.Signature)
	)

	coinName, err := getCommonCoinName(slot, tag, round)
	if err != nil {
		return 0, err
	}

	{
		signature, err := getCommonCoinNameSigned(slot, tag, round, privKey)
		if err != nil {
			return 0, err
		}
	
		err = broadcast(CommonCoinMessage{
			Source: id,
			Slot:   slot,
			Tag:    tag,
			Round:  round,
			Sig:    signature,
		})
		if err != nil {
			return 0, err
		}
	}

	for {
		select {
		case msg := <-receiveChannel:

			// ignore messages from other rounds
			if msg.Slot != slot || msg.Tag != tag || msg.Round != round {
				continue
			}

			// verify signature validity
			err := tbls.Verify(pubKeys[msg.Source], coinName, msg.Sig)
			if err != nil {
				log.Info(ctx, "Node id received invalid signature from source", z.Uint("id", id), z.Uint("slot", slot), z.Uint("tag", tag), z.Uint("r", round), z.Uint("source", msg.Source))
				continue
			}

			signatures[int(msg.Source)] = msg.Sig

			if len(signatures) >= int(f)+1 {

				result, err := getCommonCoinResult(ctx, slot, tag, round, pubKey, signatures)
				if err != nil {
					continue
				}

				log.Info(ctx, "Node id decided value", z.Uint("id", id), z.Uint("slot", slot), z.Uint("tag", tag), z.Uint("r", round), z.U8("coin", result))

				return result, nil
			}
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}
