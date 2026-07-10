package main

import (
	"os"
	"syscall"

	"github.com/sirupsen/logrus"
)

// waitForShutdownSignal keeps SIGHUP as an in-process configuration reload.
// It returns only when SIGINT/SIGTERM (or another shutdown signal) arrives.
func waitForShutdownSignal(signals <-chan os.Signal, forceReload func() error) os.Signal {
	for sig := range signals {
		if sig != syscall.SIGHUP {
			return sig
		}

		logrus.Info("Received SIGHUP, reloading configuration without stopping the service...")
		if forceReload == nil {
			logrus.Warn("SIGHUP reload skipped: reload handler is not configured")
			continue
		}
		if err := forceReload(); err != nil {
			logrus.Errorf("SIGHUP configuration reload failed: %v", err)
			continue
		}
		logrus.Info("SIGHUP configuration reload completed; service remains running")
	}

	return nil
}
