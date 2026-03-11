package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"security-exporter/config"
	"security-exporter/internal/collector"
	"security-exporter/internal/metrics"
	"security-exporter/internal/scanner"
)

func main() {
	configPath := flag.String("config", "/etc/obmondo/security-exporter/config.yaml", "path to config file")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	coll, err := collector.New()
	if err != nil {
		slog.Error("failed to create collector", "error", err)
		os.Exit(1)
	}

	sc, err := scanner.New(cfg.VulsServer)
	if err != nil {
		slog.Error("failed to create scanner", "error", err)
		os.Exit(1)
	}

	scanTask := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		slog.Info("starting vulnerability scan")
		result, err := sc.Scan(ctx, coll)
		if err != nil {
			slog.Error("scan failed", "error", err)
			return
		}

		metrics.Update(result)
		slog.Info("scan completed", "cves", len(result.ScannedCves))
	}

	scheduler, err := gocron.NewScheduler()
	if err != nil {
		slog.Error("failed to create scheduler", "error", err)
		os.Exit(1)
	}

	_, err = scheduler.NewJob(
		gocron.CronJob(cfg.CronExpression, false),
		gocron.NewTask(scanTask),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithStartAt(gocron.WithStartImmediately()),
	)
	if err != nil {
		slog.Error("failed to schedule job", "error", err)
		os.Exit(1)
	}

	scheduler.Start()
	slog.Info("scheduler started", "cron", cfg.CronExpression)

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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("HTTP server shutdown error", "error", err)
	}
}
