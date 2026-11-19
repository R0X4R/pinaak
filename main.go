package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/R0X4R/pinaak/pkg"
)

func main() {
	if err := run(); err != nil {
		pkg.PrintError("%v", err)
		os.Exit(1)
	}
}

func run() error {
	opts, err := pkg.ParseOptions()
	if err != nil {
		return err
	}

	if opts.NoColor {
		pkg.SetNoColor(true)
	}
	if opts.Silent {
		pkg.SetSilent(true)
	}
	if opts.JSONOutput {
		pkg.SetJSONOutput(true)
	}
	if opts.OutputFile != "" {
		if err := pkg.SetOutputFile(opts.OutputFile); err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		defer pkg.CloseOutput()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Capture interrupt signals for graceful termination
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		pkg.PrintWarning("Scan interrupted, shutting down...")
		cancel()
		<-sigChan
		os.Exit(130)
	}()

	if opts.Domain == "" && opts.SubdomainsList == "" && !pkg.HasStdin() {
		return fmt.Errorf("target domain (-d), subdomain list (-l), or piped stdin input is required")
	}

	pkg.PrintInfo("Target: %s (workers: %d, timeout: %ds)", opts.Domain, opts.Threads, opts.Timeout)

	_ = ctx
	return nil
}
