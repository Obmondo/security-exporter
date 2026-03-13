package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"security-exporter/config"
	"security-exporter/internal/collector"
	"security-exporter/internal/prommetrics"
	"security-exporter/internal/pkgscanner"
)

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run as a daemon with scheduled scanning and Prometheus metrics",
		Long: `Start the security exporter in daemon mode.

Periodically scans installed packages against the Vuls server and exposes
CVE metrics via a Prometheus HTTP endpoint.`,
		RunE: runServe,
	}
}

func runServe(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	coll, err := collector.New()
	if err != nil {
		return err
	}

	sc, err := pkgscanner.New(cfg.VulsServer)
	if err != nil {
		return err
	}

	const (
		scanTimeout     = 5 * time.Minute
		shutdownTimeout = 10 * time.Second
	)

	scanTask := func() {
		ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
		defer cancel()

		slog.Info("starting vulnerability scan")
		result, err := sc.Scan(ctx, coll)
		if err != nil {
			slog.Error("scan failed", "error", err)
			return
		}

		prommetrics.Update(result)
		slog.Info("scan completed", "cves", len(result.ScannedCves))
	}

	scheduler, err := gocron.NewScheduler()
	if err != nil {
		return err
	}

	_, err = scheduler.NewJob(
		gocron.DurationJob(cfg.ScanInterval.Duration),
		gocron.NewTask(scanTask),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithStartAt(gocron.WithStartImmediately()),
	)
	if err != nil {
		return err
	}

	scheduler.Start()
	slog.Info("scheduler started", "interval", cfg.ScanInterval.Duration)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    cfg.ListenAddress,
		Handler: mux,
	}

	go func() {
		slog.Info("starting HTTP server", "address", cfg.ListenAddress)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("shutting down")
	if err := scheduler.Shutdown(); err != nil {
		slog.Error("scheduler shutdown error", "error", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	return server.Shutdown(ctx)
}
