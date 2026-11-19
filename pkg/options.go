package pkg

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/goflags"
	"gopkg.in/yaml.v3"
)

// Options holds command line configurations for the origin discovery run.
type Options struct {
	Domain            string
	SubdomainsList    string
	ConfigFile        string
	OutputFile        string
	JSONOutput        bool
	Silent            bool
	NoColor           bool
	Threads           int
	Timeout           int
	SkipVerification  bool
	ShodanKey         string
	CensysID          string
	CensysSecret      string
	FofaEmail         string
	FofaKey           string
	SecurityTrailsKey string
}

// ConfigFile represents options stored in ~/.config/pinaak/config.yaml.
type ConfigFile struct {
	ShodanKey         string `yaml:"shodan-key"`
	CensysID          string `yaml:"censys-id"`
	CensysSecret      string `yaml:"censys-secret"`
	FofaEmail         string `yaml:"fofa-email"`
	FofaKey           string `yaml:"fofa-key"`
	SecurityTrailsKey string `yaml:"securitytrails-key"`
}

// ParseOptions parses CLI flags and ensures valid input configuration.
func ParseOptions() (*Options, error) {
	opts := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("pinaak - Origin IP discovery behind CDNs and WAFs")

	// Prevent goflags from attempting to create unwanted directories in AppData
	stubConfig := filepath.Join(os.TempDir(), "pinaak-flags-stub.yaml")
	if _, err := os.Stat(stubConfig); os.IsNotExist(err) {
		_ = os.WriteFile(stubConfig, []byte("# pinaak flagset stub\n"), 0644)
	}
	flagSet.SetConfigFilePath(stubConfig)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&opts.Domain, "domain", "d", "", "Target domain to discover origin IP for"),
		flagSet.StringVarP(&opts.SubdomainsList, "list", "l", "", "File containing already-known subdomains (optional)"),
		flagSet.StringVar(&opts.ConfigFile, "config", "", "Configuration file path (default: ~/.config/pinaak/config.yaml)"),
	)

	flagSet.CreateGroup("api", "API Keys",
		flagSet.StringVar(&opts.ShodanKey, "shodan-key", "", "Shodan API key for favicon and cert lookups"),
		flagSet.StringVar(&opts.CensysID, "censys-id", "", "Censys API ID for certificate search"),
		flagSet.StringVar(&opts.CensysSecret, "censys-secret", "", "Censys API secret for certificate search"),
		flagSet.StringVar(&opts.FofaEmail, "fofa-email", "", "FOFA account email"),
		flagSet.StringVar(&opts.FofaKey, "fofa-key", "", "FOFA API key"),
		flagSet.StringVar(&opts.SecurityTrailsKey, "securitytrails-key", "", "SecurityTrails API key for historical DNS records"),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVarP(&opts.Threads, "threads", "t", 25, "Number of concurrent workers"),
		flagSet.IntVar(&opts.Timeout, "timeout", 10, "Network timeout in seconds"),
	)

	flagSet.CreateGroup("verification", "Verification",
		flagSet.BoolVar(&opts.SkipVerification, "skip-verify", false, "Skip HTTP Host header verification on candidate IPs"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opts.OutputFile, "output", "o", "", "File path to save discovered results"),
		flagSet.BoolVarP(&opts.JSONOutput, "json", "j", false, "Output results in JSON format"),
		flagSet.BoolVarP(&opts.Silent, "silent", "s", false, "Suppress non-essential status logs"),
		flagSet.BoolVarP(&opts.NoColor, "no-color", "nc", false, "Disable ANSI color output"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, err
	}

	// Load configuration file from ~/.config/pinaak/config.yaml or custom path
	configPath := opts.ConfigFile
	if configPath == "" {
		configPath = getDefaultConfigPath()
	}
	cfg, err := loadConfigFile(configPath)
	if err != nil {
		return nil, err
	}
	if cfg != nil {
		applyConfigDefaults(opts, cfg)
	}

	// Environment variable fallbacks for API credentials
	applyEnvDefaults(opts)

	if opts.Threads <= 0 {
		opts.Threads = 25
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10
	}

	if opts.SubdomainsList != "" {
		stat, err := os.Stat(opts.SubdomainsList)
		if err != nil {
			return nil, fmt.Errorf("subdomains list file not found: %w", err)
		}
		if stat.IsDir() {
			return nil, fmt.Errorf("subdomains list path is a directory: %s", opts.SubdomainsList)
		}
	}

	return opts, nil
}

// HasStdin returns true if standard input is connected to a pipe or redirected file.
func HasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func getDefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "pinaak", "config.yaml")
}

func loadConfigFile(path string) (*ConfigFile, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading config file failed: %w", err)
	}
	var cfg ConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file failed: %w", err)
	}
	return &cfg, nil
}

func applyConfigDefaults(opts *Options, cfg *ConfigFile) {
	if opts.ShodanKey == "" {
		opts.ShodanKey = cfg.ShodanKey
	}
	if opts.CensysID == "" {
		opts.CensysID = cfg.CensysID
	}
	if opts.CensysSecret == "" {
		opts.CensysSecret = cfg.CensysSecret
	}
	if opts.FofaEmail == "" {
		opts.FofaEmail = cfg.FofaEmail
	}
	if opts.FofaKey == "" {
		opts.FofaKey = cfg.FofaKey
	}
	if opts.SecurityTrailsKey == "" {
		opts.SecurityTrailsKey = cfg.SecurityTrailsKey
	}
}

func applyEnvDefaults(opts *Options) {
	if opts.ShodanKey == "" {
		opts.ShodanKey = os.Getenv("SHODAN_API_KEY")
	}
	if opts.CensysID == "" {
		opts.CensysID = os.Getenv("CENSYS_API_ID")
	}
	if opts.CensysSecret == "" {
		opts.CensysSecret = os.Getenv("CENSYS_API_SECRET")
	}
	if opts.FofaEmail == "" {
		opts.FofaEmail = os.Getenv("FOFA_EMAIL")
	}
	if opts.FofaKey == "" {
		opts.FofaKey = os.Getenv("FOFA_KEY")
	}
	if opts.SecurityTrailsKey == "" {
		opts.SecurityTrailsKey = os.Getenv("SECURITYTRAILS_API_KEY")
	}
}
