// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"time"

	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
)

type exitConfig struct {
	BeaconNodeURL    string
	ValidatorPubkey  string
	PrivateKeyPath   string
	ValidatorKeysDir string
	LockFilePath     string
	PublishAddress   string
	ExitEpoch        uint64
	FetchedExitPath  string
	PlaintextOutput  bool
	ExitFromFilePath string
	Log              log.Config
}

func newExitCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "exit",
		Short: "Exit a distributed validator.",
		Long:  "Sign and broadcast distributed validator exit messages using a remote API.",
	}

	root.AddCommand(cmds...)

	return root
}

type exitFlag int

const (
	publishAddress exitFlag = iota
	beaconNodeURL
	privateKeyPath
	lockFilePath
	validatorKeysDir
	validatorPubkey
	exitEpoch
	exitFromFile
)

func (ef exitFlag) String() string {
	switch ef {
	case publishAddress:
		return "publish-address"
	case beaconNodeURL:
		return "beacon-node-url"
	case privateKeyPath:
		return "private-key-file"
	case lockFilePath:
		return "lock-file"
	case validatorKeysDir:
		return "validator-keys-dir"
	case validatorPubkey:
		return "validator-public-key"
	case exitEpoch:
		return "exit-epoch"
	case exitFromFile:
		return "exit-from-file"
	default:
		return "unknown"
	}
}

type exitCLIFlag struct {
	flag     exitFlag
	required bool
}

func bindExitFlags(cmd *cobra.Command, config *exitConfig, flags []exitCLIFlag) {
	for _, f := range flags {
		flag := f.flag

		switch flag {
		case publishAddress:
			cmd.Flags().StringVar(&config.PublishAddress, publishAddress.String(), "https://api.obol.tech", "The URL of the remote API.")
		case beaconNodeURL:
			cmd.Flags().StringVar(&config.BeaconNodeURL, beaconNodeURL.String(), "", "Beacon node URL.")
		case privateKeyPath:
			cmd.Flags().StringVar(&config.PrivateKeyPath, privateKeyPath.String(), ".charon/charon-enr-private-key", "The path to the charon enr private key file. ")
		case lockFilePath:
			cmd.Flags().StringVar(&config.LockFilePath, lockFilePath.String(), ".charon/cluster-lock.json", "The path to the cluster lock file defining the distributed validator cluster.")
		case validatorKeysDir:
			cmd.Flags().StringVar(&config.ValidatorKeysDir, validatorKeysDir.String(), ".charon/validator_keys", "Path to the directory containing the validator private key share files and passwords.")
		case validatorPubkey:
			cmd.Flags().StringVar(&config.ValidatorPubkey, validatorPubkey.String(), "", "Public key of the validator to exit, must be present in the cluster lock manifest.")
		case exitEpoch:
			cmd.Flags().Uint64Var(&config.ExitEpoch, exitEpoch.String(), 162304, "Exit epoch at which the validator will exit, must be the same across all the partial exits.")
		case exitFromFile:
			cmd.Flags().StringVar(&config.ExitFromFilePath, exitFromFile.String(), "", "Retrieves a signed exit message from a pre-prepared file instead of --publish-address.")
		}

		if f.required {
			mustMarkFlagRequired(cmd, flag.String())
		}
	}
}

func eth2Client(ctx context.Context, u string) (eth2wrap.Client, error) {
	bnHTTPClient, err := eth2http.New(ctx,
		eth2http.WithAddress(u),
		eth2http.WithLogLevel(1), // zerolog.InfoLevel
	)
	if err != nil {
		return nil, errors.Wrap(err, "can't connect to beacon node")
	}

	bnClient := bnHTTPClient.(*eth2http.Service)

	return eth2wrap.AdaptEth2HTTP(bnClient, 10*time.Second), nil
}

// signExit signs a voluntary exit message for valIdx with the given keyShare.
func signExit(ctx context.Context, eth2Cl eth2wrap.Client, valIdx eth2p0.ValidatorIndex, keyShare tbls.PrivateKey, exitEpoch eth2p0.Epoch) (eth2p0.SignedVoluntaryExit, error) {
	exit := &eth2p0.VoluntaryExit{
		Epoch:          exitEpoch,
		ValidatorIndex: valIdx,
	}

	sigData, err := sigDataForExit(ctx, *exit, eth2Cl, exitEpoch)
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "exit hash tree root")
	}

	sig, err := tbls.Sign(keyShare, sigData[:])
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "signing error")
	}

	return eth2p0.SignedVoluntaryExit{
		Message:   exit,
		Signature: eth2p0.BLSSignature(sig),
	}, nil
}

// sigDataForExit returns the hash tree root for the given exit message, at the given exit epoch.
func sigDataForExit(ctx context.Context, exit eth2p0.VoluntaryExit, eth2Cl eth2wrap.Client, exitEpoch eth2p0.Epoch) ([32]byte, error) {
	sigRoot, err := exit.HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "exit hash tree root")
	}

	domain, err := signing.GetDomain(ctx, eth2Cl, signing.DomainExit, exitEpoch)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "get domain")
	}

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "signing data hash tree root")
	}

	return sigData, nil
}
