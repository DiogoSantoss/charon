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
type CommonCoin struct {
	Id uint
	Slot uint
	Tag uint
	Round uint
	PubKey tbls.PublicKey
	PubKeys map[uint]tbls.PublicKey
	PrivKey tbls.PrivateKey
}

func NewCommonCoin(id uint, slot uint, tag uint, round uint, pubKey tbls.PublicKey, pubKeys map[uint]tbls.PublicKey, privKey tbls.PrivateKey) *CommonCoin {
	return &CommonCoin{
		Id: id,
		Slot: slot,
		Tag: tag,
		Round: round,
		PubKey: pubKey,
		PubKeys: pubKeys,
		PrivKey: privKey,
	}
}

// GetCommonCoinName returns a unique nonce representing the coin name
// for the given slot, tag, and round
func (c *CommonCoin) getCommonCoinName() ([]byte, error) {
	name := fmt.Sprintf("AleaCommmonCoin%v%v%v", c.Slot, c.Tag, c.Round)
	nonce := sha256.Sum256([]byte(name))

	return nonce[:], nil
}

// GetCommonCoinNameSigned returns a signature share of the coin name
func (c *CommonCoin) getCommonCoinNameSigned() (tbls.Signature, error) {
	name, err := c.getCommonCoinName()
	if err != nil {
		return tbls.Signature{}, err
	}

	return tbls.Sign(c.PrivKey, name)
}

// GetCommonCoinResult returns the coin result by threshold aggregating the signatures
func (c *CommonCoin) getCommonCoinResult(ctx context.Context, signatures map[int]tbls.Signature) (byte, error) {
	totalSig, err := tbls.ThresholdAggregate(signatures)
	if err != nil {
		return 0, err
	}

	sid, err := c.getCommonCoinName()
	if err != nil {
		return 0, err
	}

	err = tbls.Verify(c.PubKey, sid, totalSig)
	if err != nil {
		log.Info(ctx, "Failed to verify aggregate signature")
		return 0, err
	}

	return totalSig[0] & 1, nil
}

func (c *CommonCoin) SampleCoin(ctx context.Context, broadcast func(CommonCoinMessage) error, receiveChannel <-chan CommonCoinMessage) (byte, error) {

	ctx = log.WithTopic(ctx, "commoncoin")

	log.Info(ctx, "Node id sampled common coin", z.Uint("id", c.Id), z.Uint("slot", c.Slot), z.Uint("tag", c.Tag), z.Uint("r", c.Round))

	// === State ===
	var (
		f          uint = 1 // should get F from somewhere, e.g. GetSmallQuorumSize()
		signatures      = make(map[int]tbls.Signature)
	)

	coinName, err := c.getCommonCoinName()
	if err != nil {
		return 0, err
	}

	{
		signature, err := c.getCommonCoinNameSigned()
		if err != nil {
			return 0, err
		}

		err = broadcast(CommonCoinMessage{
			Source: c.Id,
			Slot:   c.Slot,
			Tag:    c.Tag,
			Round:  c.Round,
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
			if msg.Slot != c.Slot || msg.Tag != c.Tag || msg.Round != c.Round {
				continue
			}

			// verify signature validity
			err := tbls.Verify(c.PubKeys[msg.Source], coinName, msg.Sig)
			if err != nil {
				log.Info(ctx, "Node id received invalid signature from source", z.Uint("id", c.Id), z.Uint("slot", c.Slot), z.Uint("tag", c.Tag), z.Uint("r", c.Round), z.Uint("source", msg.Source))
				continue
			}

			signatures[int(msg.Source)] = msg.Sig

			if len(signatures) >= int(f)+1 {

				result, err := c.getCommonCoinResult(ctx, signatures)
				if err != nil {
					continue
				}

				log.Info(ctx, "Node id decided value", z.Uint("id", c.Id), z.Uint("slot", c.Slot), z.Uint("tag", c.Tag), z.Uint("r", c.Round), z.U8("coin", result))

				return result, nil
			}
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}
