package aba

import (
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/obolnetwork/charon/tbls"
)

// CommonCoin implementation from the paper: "The Honey Badger of BFT Protocols"
// Link: https://eprint.iacr.org/2016/199.pdf (Figure 12)

// GetCommonCoinName returns a unique nonce representing the coin name
// for the given slot and round
func GetCommonCoinName(slot int, round int) ([]byte, error) {
	name := fmt.Sprintf("AleaCommmonCoin%v%v", slot, round)
	nonce := sha256.Sum256([]byte(name))

	return nonce[:], nil
}

// GetCommonCoinNameSigned returns a signature share of the coin name
func GetCommonCoinNameSigned(slot int, round int, privateKey tbls.PrivateKey) (tbls.Signature, error) {
	name, err := GetCommonCoinName(slot, round)
	if err != nil {
		return tbls.Signature{}, err
	}

	return tbls.Sign(privateKey, name)
}

// GetCommonCoinResult returns the coin result by threshold aggregating the signatures
func GetCommonCoinResult(signatures map[int]tbls.Signature) (uint, error) {
	// TODO: Does this threshold aggregate works in the following situation ?
	// have f+2 signatures, one of them is invalid, still f+1 valid
	// does the aggregation fail or not ?
	totalSig, err := tbls.ThresholdAggregate(signatures)
	if err != nil {
		return 0, err
	}

	return uint(totalSig[0] & 1), nil
}

type TempABAMessage struct {
	Id  int
	Sig tbls.Signature
}

func Run(id int, slot int, round int, privateKey tbls.PrivateKey, broadcast func(int, tbls.Signature) error, receiveChannel <-chan TempABAMessage) (uint, error) {

	log.Printf("Node %d starting ABA instance\n", id)

	// === State ===
	var (
		f          int = 1 // should get F from somewhere, e.g. GetSmallQuorumSize()
		signatures     = make(map[int]tbls.Signature)
	)

	{
		signature, err := GetCommonCoinNameSigned(slot, round, privateKey)
		if err != nil {
			return 0, err
		}
		signatures[id] = signature
		log.Printf("Node %d is going to broadcast signature\n", id)
		err = broadcast(id, signature)
		log.Printf("Node %d broadcasted signature\n", id)
		if err != nil {
			return 0, err
		}
	}

	for {
		select {
		case msg := <-receiveChannel:

			log.Printf("Node %d received signature from %d\n", id, msg.Id)

			signatures[msg.Id] = msg.Sig

			if len(signatures) >= f+1 {

				result, err := GetCommonCoinResult(signatures)
				if err != nil {
					return 0, err
				}

				log.Printf("Node %d decided with %d\n", id, result)

				return result, nil
			}
		}
	}
}
