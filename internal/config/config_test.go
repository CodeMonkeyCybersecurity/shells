package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoggerConfig(t *testing.T) {
	config := LoggerConfig{
		Level:       "debug",
		Format:      "json",
		OutputPaths: []string{"stdout", "stderr"},
	}

	assert.Equal(t, "debug", config.Level)
	assert.Equal(t, "json", config.Format)
	assert.Contains(t, config.OutputPaths, "stdout")
}

func TestDatabaseConfig(t *testing.T) {
	config := DatabaseConfig{
		Driver:          "sqlite",
		DSN:             ":memory:",
		MaxConnections:  10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
	}

	assert.Equal(t, "sqlite", config.Driver)
	assert.Equal(t, ":memory:", config.DSN)
	assert.Equal(t, 10, config.MaxConnections)
}

func TestRedisConfig(t *testing.T) {
	config := RedisConfig{
		Addr:         "localhost:6379",
		Password:     "",
		DB:           0,
		MaxRetries:   3,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	assert.Equal(t, "localhost:6379", config.Addr)
	assert.Equal(t, 0, config.DB)
	assert.Equal(t, 3, config.MaxRetries)
}

func TestWorkerConfig(t *testing.T) {
	config := WorkerConfig{
		Count:             4,
		QueuePollInterval: 1 * time.Second,
		MaxRetries:        3,
		RetryDelay:        5 * time.Second,
	}

	assert.Equal(t, 4, config.Count)
	assert.Equal(t, 1*time.Second, config.QueuePollInterval)
	assert.Equal(t, 3, config.MaxRetries)
}

func TestNmapConfig(t *testing.T) {
	config := NmapConfig{
		BinaryPath: "/usr/bin/nmap",
		Timeout:    30 * time.Second,
		Profiles: map[string]string{
			"default": "-sS -sV",
			"quick":   "-sS -F",
		},
	}

	assert.Equal(t, "/usr/bin/nmap", config.BinaryPath)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Contains(t, config.Profiles, "default")
	assert.Equal(t, "-sS -sV", config.Profiles["default"])
}

func TestSSLConfig(t *testing.T) {
	config := SSLConfig{
		Timeout:         30 * time.Second,
		FollowRedirects: true,
		CheckRevocation: true,
	}

	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.True(t, config.FollowRedirects)
	assert.True(t, config.CheckRevocation)
}

func TestFullConfig(t *testing.T) {
	config := Config{
		Logger: LoggerConfig{
			Level:  "info",
			Format: "console",
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			DSN:    "./test.db",
		},
		Redis: RedisConfig{
			Addr: "localhost:6379",
			DB:   0,
		},
		Worker: WorkerConfig{
			Count:      2,
			MaxRetries: 3,
		},
	}

	assert.Equal(t, "info", config.Logger.Level)
	assert.Equal(t, "sqlite", config.Database.Driver)
	assert.Equal(t, "localhost:6379", config.Redis.Addr)
	assert.Equal(t, 2, config.Worker.Count)
}
