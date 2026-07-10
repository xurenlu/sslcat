package main

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestWaitForShutdownSignalReloadsOnSIGHUPAndKeepsRunning(t *testing.T) {
	signals := make(chan os.Signal, 2)
	signals <- syscall.SIGHUP
	signals <- syscall.SIGTERM

	reloadCalls := 0
	got := waitForShutdownSignal(signals, func() error {
		reloadCalls++
		return nil
	})

	if got != syscall.SIGTERM {
		t.Fatalf("shutdown signal: got %v, want %v", got, syscall.SIGTERM)
	}
	if reloadCalls != 1 {
		t.Fatalf("reload calls: got %d, want 1", reloadCalls)
	}
}

func TestWaitForShutdownSignalReloadFailureDoesNotStopService(t *testing.T) {
	signals := make(chan os.Signal, 2)
	signals <- syscall.SIGHUP
	signals <- syscall.SIGINT

	reloadCalls := 0
	got := waitForShutdownSignal(signals, func() error {
		reloadCalls++
		return errors.New("reload failed")
	})

	if got != syscall.SIGINT {
		t.Fatalf("shutdown signal: got %v, want %v", got, syscall.SIGINT)
	}
	if reloadCalls != 1 {
		t.Fatalf("reload calls: got %d, want 1", reloadCalls)
	}
}
