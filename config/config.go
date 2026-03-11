package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	VulsServer     VulsServer `yaml:"vuls_server"`
	ListenAddress  string     `yaml:"listen_address"`
	CronExpression string     `yaml:"cron_expression"`
}

type VulsServer struct {
	URL      string   `yaml:"url"`
	Timeout  Duration `yaml:"timeout"`
	CertFile string   `yaml:"cert_file"`
	KeyFile  string   `yaml:"key_file"`
	CAFile   string   `yaml:"ca_file"`
}

// Duration wraps time.Duration for YAML unmarshaling.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}
