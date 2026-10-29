// This command is an isolated single-peer architecture experiment, not an
// alternative production wg-quic entry point.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	armorbind "github.com/RC-CHN/wg-quic/internal/bind"
	"github.com/RC-CHN/wg-quic/internal/kernelrelay"
	"github.com/RC-CHN/wg-quic/internal/transport/obfs"
)

type config struct {
	Interface            string `json:"interface"`
	KernelEndpoint       string `json:"kernel_endpoint"`
	BootstrapListen      string `json:"bootstrap_listen"`
	PeerQUICEndpoint     string `json:"peer_quic_endpoint"`
	QUICListenPort       uint16 `json:"quic_listen_port"`
	PeerPublicKey        string `json:"peer_public_key"`
	TestPrivateKeyFile   string `json:"test_private_key_file"`
	TestPresharedKeyFile string `json:"test_preshared_key_file"`
	FECMode              string `json:"fec_mode"`
	ObfsMode             string `json:"obfs_mode"`
}

func main() {
	path := flag.String("config", "", "JSON config for fresh disposable test keys/interfaces only")
	statsEvery := flag.Duration("stats-interval", time.Second, "JSON telemetry interval; 0 means start/final only")
	flag.Parse()
	if err := run(*path, *statsEvery); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string, statsEvery time.Duration) error {
	if path == "" || statsEvery < 0 {
		return errors.New("config required; stats-interval must be nonnegative")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 16385))
	decoder.DisallowUnknownFields()
	var cfg config
	if err := decoder.Decode(&cfg); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing config data")
	}
	var relayConfig kernelrelay.Config
	if relayConfig.KernelEndpoint, err = netip.ParseAddrPort(cfg.KernelEndpoint); err != nil {
		return err
	}
	if relayConfig.BootstrapListen, err = netip.ParseAddrPort(cfg.BootstrapListen); err != nil {
		return err
	}
	if relayConfig.PeerQUICEndpoint, err = netip.ParseAddrPort(cfg.PeerQUICEndpoint); err != nil {
		return err
	}
	peer, err := decodeKey(cfg.PeerPublicKey)
	if err != nil {
		return errors.New("invalid test peer public key")
	}
	relayConfig.PeerPublicKey = peer
	relayConfig.QUICListenPort = cfg.QUICListenPort
	relayConfig.Observer = kernelrelay.LinuxObserver{Interface: cfg.Interface, PeerPublicKey: peer}
	bindConfig := armorbind.DefaultConfig()
	if cfg.FECMode != "" {
		bindConfig.FECMode = cfg.FECMode
	}
	if cfg.ObfsMode == "" {
		cfg.ObfsMode = "salamander"
	}
	bindConfig.ObfsMode = cfg.ObfsMode
	if bindConfig.FECMode != "auto" && bindConfig.FECMode != "off" {
		return errors.New("fec_mode must be auto or off")
	}
	if cfg.ObfsMode == "salamander" {
		private, err := readTestKey(cfg.TestPrivateKeyFile)
		if err != nil {
			return err
		}
		var psk []byte
		if cfg.TestPresharedKeyFile != "" {
			value, err := readTestKey(cfg.TestPresharedKeyFile)
			if err != nil {
				clear(private[:])
				return err
			}
			psk = value[:]
		}
		key, err := obfs.DeriveWireGuardKey(private[:], peer[:], psk)
		clear(private[:])
		clear(psk)
		if err != nil {
			return err
		}
		bindConfig.ObfsKeys = []obfs.Key{key}
	} else if cfg.ObfsMode != "none" {
		return errors.New("obfs_mode must be salamander or none")
	}
	relayConfig.Bind = armorbind.New(bindConfig)
	if len(bindConfig.ObfsKeys) > 0 {
		release, err := relayConfig.Bind.AcquireEndpointKey(relayConfig.PeerQUICEndpoint, bindConfig.ObfsKeys[0])
		if err != nil {
			return err
		}
		defer release()
	}
	relay, err := kernelrelay.Open(relayConfig)
	if err != nil {
		return err
	}
	defer relay.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	output := json.NewEncoder(os.Stdout)
	emit := func(event string) error {
		return output.Encode(struct {
			Event string            `json:"event"`
			At    time.Time         `json:"at"`
			PID   int               `json:"pid"`
			Stats kernelrelay.Stats `json:"stats"`
		}{event, time.Now(), os.Getpid(), relay.Stats()})
	}
	if err := emit("ready"); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- relay.Run(ctx) }()
	var ticks <-chan time.Time
	if statsEvery > 0 {
		ticker := time.NewTicker(statsEvery)
		defer ticker.Stop()
		ticks = ticker.C
	}
	for {
		select {
		case err := <-done:
			if emitErr := emit("stopped"); emitErr != nil {
				return emitErr
			}
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		case <-ticks:
			if err := emit("stats"); err != nil {
				stop()
				<-done
				return err
			}
		}
	}
}

func decodeKey(value string) ([32]byte, error) {
	var key [32]byte
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	defer clear(data)
	if err != nil || len(data) != len(key) {
		return key, errors.New("key must be 32 base64 bytes")
	}
	copy(key[:], data)
	return key, nil
}

func readTestKey(path string) ([32]byte, error) {
	var empty [32]byte
	file, err := os.Open(path)
	if err != nil {
		return empty, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return empty, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return empty, errors.New("test key must be a regular file readable only by its owner")
	}
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return empty, err
	}
	defer clear(data)
	if len(data) > 256 {
		return empty, errors.New("test key file is too large")
	}
	return decodeKey(string(data))
}
