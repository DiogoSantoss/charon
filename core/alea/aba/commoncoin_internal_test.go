package aba

import (
	"testing"

	"github.com/obolnetwork/charon/tbls"
	"github.com/stretchr/testify/require"
)

func TestGetCommonCoinName(t *testing.T) {
	coinName, err := getCommonCoinName(0, 0)
	require.NoError(t, err)
	require.NotEmpty(t, coinName)
}

func TestGetCommonCoinResult(t *testing.T) {
	secret, _ := tbls.GenerateSecretKey()
	public, _ := tbls.SecretToPublicKey(secret)
	shares, _ := tbls.ThresholdSplit(secret, 4, 2)

	signatures := map[int]tbls.Signature{}

	// wait for f+1 before revealing the coin
	for i := 0; i < 2; i++ {
		signature, err := getCommonCoinNameSigned(0, 0, shares[i+1])
		require.NoError(t, err)
		signatures[i+1] = signature
	}

	result, err := getCommonCoinResult(0, 0, public, signatures)
	require.NoError(t, err)

	require.Condition(t, func() (success bool) {
		return result == 0 || result == 1
	})
}

// TODO: this test fails because tbls.ThresholdAggregate fails
// if one signature is invalid
// Should find a way to succed if f+1 out of m sig share are valid
func TestGetCommonCoinResultBadSignature(t *testing.T) {

	secret, _ := tbls.GenerateSecretKey()
	public, _ := tbls.SecretToPublicKey(secret)
	shares, _ := tbls.ThresholdSplit(secret, 4, 2)

	signatures := map[int]tbls.Signature{}

	// wait for f+2 before revealing the coin
	for i := 0; i < 3; i++ {
		signature, err := getCommonCoinNameSigned(0, 0, shares[i+1])
		require.NoError(t, err)
		signatures[i+1] = signature
	}

	// inject a bad signature (f+1 good signatures and 1 bad)
	bad_signatures := map[int]tbls.Signature{}
	for i := 1; i < 3; i++ {
		bad_signatures[i+1] = signatures[i+1]
	}

	another_secret, _ := tbls.GenerateSecretKey()
	signature, err := getCommonCoinNameSigned(0, 0, another_secret)
	require.NoError(t, err)
	bad_signatures[1] = signature

	bad_sigs_result, err := getCommonCoinResult(0, 0, public, bad_signatures)
	require.NoError(t, err)
	result, err := getCommonCoinResult(0, 0, public, signatures)
	require.NoError(t, err)

	// TODO: Since result is zero or one there is a probability
	// that the bad result is the same as the good result.
	require.Condition(t, func() (success bool) {
		return result == bad_sigs_result
	})
}
