package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsAliasInConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	rcFile := filepath.Join(tmpDir, ".zshrc")

	content := `# ornek config dosyasi (zsh/bash/fish)
alias ll='ls -la'
alias gs = "git status"
	alias k='kubectl'
alias la 'ls -A'
function gco
export PATH=$PATH:/usr/local/bin
`
	if err := os.WriteFile(rcFile, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	got := IsAliasInConfigFile(rcFile)
	expected := []string{"ll", "gs", "k", "la", "gco"}

	if len(got) != len(expected) {
		t.Fatalf("expected %d aliases, got %d (%v)", len(expected), len(got), got)
	}

	for i, exp := range expected {
		if got[i] != exp {
			t.Errorf("expected alias %q at index %d, got %q", exp, i, got[i])
		}
	}
}

func TestIsValidCommand(t *testing.T) {
	savedAliases, savedAliasSet := aliases, aliasSet
	defer func() { aliases, aliasSet = savedAliases, savedAliasSet }()

	aliases = []string{"ll", "mycustomcmd"}
	aliasSet = map[string]bool{"ll": true, "mycustomcmd": true}

	validCases := []string{
		"cd",
		"export",
		"unset",
		"alias",
		"ll",
		"mycustomcmd",
		"GOOS=linux go build",
		"FOO=bar",
		"ls",
	}

	for _, tc := range validCases {
		if !isValidCommand(tc) {
			t.Errorf("expected %q to be valid command, got false", tc)
		}
	}

	invalidCases := []string{
		"GizliSifre123!",
		"hunter2_parola",
	}

	for _, tc := range invalidCases {
		if isValidCommand(tc) {
			t.Errorf("expected %q to be invalid (potential password), got true", tc)
		}
	}
}

func TestExtractSecretPassword(t *testing.T) {
	cmd, err := extractSecretPassword(": 1689951023:0;git status")
	if err != nil || cmd != "git" {
		t.Errorf("expected 'git', got %q (err: %v)", cmd, err)
	}

	cmd2, err := extractSecretPassword("GOOS=linux go build")
	if err != nil || cmd2 != "go" {
		t.Errorf("expected 'go', got %q (err: %v)", cmd2, err)
	}
}

func TestDetectRegexes(t *testing.T) {
	if len(compiledRegexes) != len(secretPatterns) {
		t.Fatalf("some regex patterns failed to compile: compiled=%d, total=%d", len(compiledRegexes), len(secretPatterns))
	}

	seen := make(map[string]string, len(secretPatterns))
	for label, pattern := range secretPatterns {
		if prevLabel, exists := seen[pattern]; exists {
			t.Errorf("duplicate regex pattern between %q and %q: %s", prevLabel, label, pattern)
		}
		seen[pattern] = label
	}

	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "GitHub PAT",
			input:    "export GITHUB_TOKEN=" + "ghp_" + strings.Repeat("a1", 18),
			expected: "GitHub Personal Access Token",
		},
		{
			name:     "AWS Access Key",
			input:    "aws configure set aws_access_key_id " + "AKIA" + "IOSFODNN7EXAMPLE",
			expected: "AWS Access Key ID",
		},
		{
			name:     "OpenAI Project Key",
			input:    "export OPENAI_API_KEY=" + "sk-proj-" + strings.Repeat("x9", 16),
			expected: "OpenAI API Key",
		},
		{
			name:     "Anthropic Claude Key",
			input:    "export ANTHROPIC_API_KEY=" + "sk-ant-" + strings.Repeat("b2", 20),
			expected: "Anthropic (Claude) API Key",
		},
		{
			name:     "HuggingFace Token",
			input:    "huggingface-cli login --token " + "hf_" + strings.Repeat("c3", 17),
			expected: "HuggingFace Access Token",
		},
		{
			name:     "Groq API Key",
			input:    "export GROQ_KEY=" + "gsk_" + strings.Repeat("d4", 25),
			expected: "Groq API Key",
		},
		{
			name:     "DigitalOcean PAT",
			input:    "doctl auth init -t " + "dop_v1_" + strings.Repeat("ab", 32),
			expected: "DigitalOcean Personal Token",
		},
		{
			name:     "Tailscale Key",
			input:    "tailscale up --authkey=" + "tskey-auth-" + strings.Repeat("z8", 12),
			expected: "Tailscale Auth Key",
		},
		{
			name:     "HashiCorp Vault Token",
			input:    "vault login " + "hvs." + strings.Repeat("v7", 15),
			expected: "HashiCorp Vault Token",
		},
		{
			name:     "PostgreSQL URI",
			input:    "psql postgresql://admin:gizlisifre123@db.internal.local:5432/prod",
			expected: "PostgreSQL Connection URI",
		},
		{
			name:     "MongoDB URI",
			input:    "mongosh mongodb+srv://user:pass1234@cluster0.example.mongodb.net/mydb",
			expected: "MongoDB Connection URI",
		},
		{
			name:     "Stripe Live Key",
			input:    "curl https://api.stripe.com/v1/charges -u " + "sk_live_" + strings.Repeat("k5", 13) + ":",
			expected: "Stripe Live API Key",
		},
		{
			name:     "Iyzico Secret Key",
			input:    "IYZICO_SECRET_KEY=sandbox-1234567890abcdef123456",
			expected: "Iyzico Secret Key",
		},
		{
			name:     "PayTR Merchant Key",
			input:    "PAYTR_MERCHANT_KEY=1234567890abcdef1234",
			expected: "PayTR Merchant Key",
		},
		{
			name:     "OpenSSH Private Key",
			input:    "cat -----BEGIN " + "OPENSSH PRIVATE KEY-----",
			expected: "OpenSSH Private Key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := DetectRegexes(tc.input)
			if !res[tc.expected] {
				t.Errorf("expected pattern %q to match input %q, but it did not", tc.expected, tc.input)
			}
		})
	}

	// Normal günlük komutların yanlışlıkla secret olarak yakalanmadığını doğrula
	safeCommands := []string{
		"git status",
		"ls -la /home/user",
		"docker ps -a",
		"go test -v ./...",
		"kubectl get pods -n kube-system",
	}

	for _, safeCmd := range safeCommands {
		res := DetectRegexes(safeCmd)
		for label, matched := range res {
			if matched {
				t.Errorf("false positive: safe command %q matched pattern %q", safeCmd, label)
			}
		}
	}
}

func TestMaskString(t *testing.T) {
	RedactOutput = true
	defer func() { RedactOutput = false }()

	masked := maskIfRedacted("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
	if masked == "ghp_1234567890abcdefghijklmnopqrstuvwxyz" {
		t.Errorf("expected secret to be masked, got plain string")
	}
}

func TestJoinLogicalLines(t *testing.T) {
	lines := []string{
		": 1689951023:0;curl -X POST \\",
		"  -H \"Authorization: Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyz\" \\",
		"  https://api.github.com/user",
		": 1689951100:0;git status",
	}

	got := joinLogicalLines(lines)
	if len(got) != 2 {
		t.Fatalf("expected 2 logical commands, got %d: %#v", len(got), got)
	}

	wantFirst := ": 1689951023:0;curl -X POST -H \"Authorization: Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyz\" https://api.github.com/user"
	if strings.Join(strings.Fields(got[0]), " ") != strings.Join(strings.Fields(wantFirst), " ") {
		t.Errorf("continuation join mismatch:\n got: %q\nwant: %q", got[0], wantFirst)
	}
	if got[1] != ": 1689951100:0;git status" {
		t.Errorf("unexpected second command: %q", got[1])
	}
}

func TestJoinLogicalLinesFlushesTrailingContinuation(t *testing.T) {
	lines := []string{": 1:0;echo hello \\"}
	got := joinLogicalLines(lines)
	if len(got) != 1 {
		t.Fatalf("expected a trailing continuation to be flushed, got %d", len(got))
	}
	if strings.TrimSpace(got[0]) != ": 1:0;echo hello" {
		t.Errorf("unexpected flush result: %q", got[0])
	}
}

func TestProcessZshHistoryMultiLine(t *testing.T) {
	tmpDir := t.TempDir()
	histFile := filepath.Join(tmpDir, ".zsh_history")

	content := ": 1689951023:0;curl -X POST \\\n" +
		"  -H \"Authorization: Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyz\" \\\n" +
		"  https://api.github.com/user\n"
	if err := os.WriteFile(histFile, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp history: %v", err)
	}

	// Birleştirme mantığı doğru olmalı: 3 fiziksel satır -> 1 mantıksal komut.
	raw, err := os.ReadFile(histFile)
	if err != nil {
		t.Fatalf("failed to read temp history: %v", err)
	}
	logical := joinLogicalLines(strings.Split(strings.TrimRight(string(raw), "\n"), "\n"))
	if len(logical) != 1 {
		t.Fatalf("expected 1 joined command, got %d: %#v", len(logical), logical)
	}
	if !strings.Contains(logical[0], "ghp_1234567890abcdefghijklmnopqrstuvwxyz") {
		t.Errorf("expected continuation token to survive the join, got %q", logical[0])
	}

	ProcessZshHistoryFileRegex(histFile)
	ProcessZshHistoryFile(histFile)
}

func TestExtractFishCommand(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"- cmd: git status", "git status", true},
		{"- cmd: set -x OPENAI_API_KEY sk-proj-abc", "set -x OPENAI_API_KEY sk-proj-abc", true},
		{"- cmd: ", "", false},
		{"  when: 1689951000", "", false},
		{"not a history line", "", false},
	}

	for _, tc := range cases {
		got, ok := extractFishCommand(tc.line)
		if ok != tc.ok || got != tc.want {
			t.Errorf("extractFishCommand(%q) = (%q, %v), want (%q, %v)", tc.line, got, ok, tc.want, tc.ok)
		}
	}
}

func TestProcessFishHistory(t *testing.T) {
	tmpDir := t.TempDir()
	fishHist := filepath.Join(tmpDir, "fish_history")

	content := "- cmd: git status\n" +
		"  when: 1689951000\n" +
		"- cmd: set -x OPENAI_API_KEY sk-proj-1234567890abcdefghijklmnopqrstuvwxyz123456\n" +
		"  when: 1689951010\n" +
		"- cmd: YanlisliklaFishSifresi123\n" +
		"  when: 1689951020\n"
	if err := os.WriteFile(fishHist, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp fish history: %v", err)
	}

	// Parser'ın beklenen sayıda ve içerikte komut tanıdığını doğrula.
	raw, err := os.ReadFile(fishHist)
	if err != nil {
		t.Fatalf("failed to read temp fish history: %v", err)
	}
	var parsed []string
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if cmd, ok := extractFishCommand(line); ok {
			parsed = append(parsed, cmd)
		}
	}
	if len(parsed) != 3 {
		t.Fatalf("expected 3 fish commands, got %d: %#v", len(parsed), parsed)
	}
	if parsed[0] != "git status" || !strings.Contains(parsed[1], "OPENAI_API_KEY") {
		t.Errorf("unexpected parsed commands: %#v", parsed)
	}

	ProcessFishHistoryFile(fishHist)
	ProcessFishHistoryFileRegex(fishHist)
}
