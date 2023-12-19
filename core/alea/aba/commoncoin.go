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

// GetCommonCoinName returns a unique nonce representing the coin name
// for the given slot and round
func getCommonCoinName(slot int, round int) ([]byte, error) {
	name := fmt.Sprintf("AleaCommmonCoin%v%v", slot, round)
	nonce := sha256.Sum256([]byte(name))

	return nonce[:], nil
}

// GetCommonCoinNameSigned returns a signature share of the coin name
func getCommonCoinNameSigned(slot int, round int, privateKey tbls.PrivateKey) (tbls.Signature, error) {
	name, err := getCommonCoinName(slot, round)
	if err != nil {
		return tbls.Signature{}, err
	}

	return tbls.Sign(privateKey, name)
}

// GetCommonCoinResult returns the coin result by threshold aggregating the signatures
func getCommonCoinResult(slot int, round int, pubKey tbls.PublicKey, signatures map[int]tbls.Signature) (uint, error) {
	// TODO: Does this threshold aggregate works in the following situation ?
	// have f+2 signatures, one of them is invalid, still f+1 valid
	// does the aggregation fail or not ?
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
		return 0, err
	}

	return uint(totalSig[0] & 1), nil
}

// Temporary struct to send/receive messages from/to peers
type TempABAMessage struct {
	Id  int
	Sig tbls.Signature
}

func SampleCoin(ctx context.Context, id int, slot int, round int, pubKey tbls.PublicKey, privateKey tbls.PrivateKey, broadcast func(int, tbls.Signature) error, receiveChannel <-chan TempABAMessage) (uint, error) {

	log.Info(ctx, "Node id sampled common coin", z.Int("id", id))

	// === State ===
	var (
		f          int = 1 // should get F from somewhere, e.g. GetSmallQuorumSize()
		signatures     = make(map[int]tbls.Signature)
	)

	{
		signature, err := getCommonCoinNameSigned(slot, round, privateKey)
		if err != nil {
			return 0, err
		}
		signatures[id] = signature
		err = broadcast(id, signature)
		if err != nil {
			return 0, err
		}
	}

	for {
		select {
		case msg := <-receiveChannel:

			log.Info(ctx, "Node id received signature from source", z.Int("id", id), z.Int("source", msg.Id))

			signatures[msg.Id] = msg.Sig

			if len(signatures) >= f+1 {

				result, err := getCommonCoinResult(slot, round, pubKey, signatures)
				if err != nil {
					continue
				}

				log.Info(ctx, "Node id decided value", z.Int("id", id), z.Uint("value", result))

				return result, nil
			}
		}
	}
}
