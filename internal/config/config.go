package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port                int
	DatabaseURL         string
	OperatorKeyPath     string
	MMDSeconds          int
	AllowedPCR0         []string
	AllowedSubmitters   []string
	CoordinatorKeysDir  string
}

func Load() (*Config, error) {
	port := 8080
	if v := os.Getenv("ATL_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid ATL_PORT: %w", err)
		}
		port = p
	}

	dbURL := os.Getenv("ATL_DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("ATL_DATABASE_URL is required")
	}

	keyPath := os.Getenv("ATL_OPERATOR_KEY_PATH")
	if keyPath == "" {
		return nil, fmt.Errorf("ATL_OPERATOR_KEY_PATH is required")
	}

	mmd := 3600
	if v := os.Getenv("ATL_MMD_SECONDS"); v != "" {
		m, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid ATL_MMD_SECONDS: %w", err)
		}
		mmd = m
	}

	var pcr0 []string
	if v := os.Getenv("ATL_ALLOWED_PCR0"); v != "" {
		pcr0 = strings.Split(v, ",")
	}

	var submitters []string
	if v := os.Getenv("ATL_ALLOWED_SUBMITTERS"); v != "" {
		submitters = strings.Split(v, ",")
	}

	coordKeysDir := os.Getenv("ATL_COORDINATOR_KEYS_DIR")

	return &Config{
		Port:               port,
		DatabaseURL:        dbURL,
		OperatorKeyPath:    keyPath,
		MMDSeconds:         mmd,
		AllowedPCR0:        pcr0,
		AllowedSubmitters:  submitters,
		CoordinatorKeysDir: coordKeysDir,
	}, nil
}
