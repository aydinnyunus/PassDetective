/*
Copyright © 2023 Yunus AYDIN <aydinnyunus@gmail.com>
*/
package cmd

import (
	"os"
	"path/filepath"

	"github.com/aydinnyunus/PassDetective/pkg/util"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var secrets bool
var bash bool
var zsh bool
var fish bool
var all bool
var redact bool

func getHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return os.Getenv("HOME")
	}
	return home
}

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract passwords from shell history",
	Long: `The "extract" command allows you to automatically extract passwords from shell history.
By analyzing the history of shell commands, this tool can identify and extract passwords that were used during
previous commands and display them for further inspection or use.
`,
	Run: func(cmd *cobra.Command, args []string) {
		zsh, _ = cmd.Flags().GetBool("zsh")
		bash, _ = cmd.Flags().GetBool("bash")
		fish, _ = cmd.Flags().GetBool("fish")
		secrets, _ = cmd.Flags().GetBool("secrets")
		all, _ = cmd.Flags().GetBool("all")
		redact, _ = cmd.Flags().GetBool("redact")

		util.RedactOutput = redact

		if all {
			zsh = true
			bash = true
			fish = true
		}

		if !zsh && !bash && !fish {
			cmd.Println("__________                     ________           __                  __   __              \n\\______   \\____    ______ ____________ \\   ____ _/  |_  ____   ____ _/  |_|__|__  __ ____  \n |     ___/__  \\  /  ___//  ___/|    |  \\_/ __ \\\\   __\\/ __ \\_/ ___\\\\   __\\  |  \\/ // __ \\ \n |    |    / __ \\_\\___ \\ \\___ \\ |    |   \\  ___/_|  | \\  ___/_  \\___ |  | |  |\\   /\\  ___/_\n |____|   (____  /____  \\____  \\_______  /\\___  /|__|  \\___  /\\___  /|__| |__| \\_/  \\___  /\n               \\/     \\/     \\/        \\/     \\/           \\/     \\/                    \\/ ")
			cmd.Help()
			return
		}

		homeDir := getHomeDir()
		zshHistoryFile := filepath.Join(homeDir, ".zsh_history")
		zshrcFile := filepath.Join(homeDir, ".zshrc")
		bashHistoryFile := filepath.Join(homeDir, ".bash_history")
		bashrcFile := filepath.Join(homeDir, ".bashrc")
		fishHistoryFile := filepath.Join(homeDir, ".local", "share", "fish", "fish_history")
		fishConfigFile := filepath.Join(homeDir, ".config", "fish", "config.fish")

		// --secrets ile seçilen tüm kabukları (zsh, bash, fish) sırayla taraması için
		// önceki os.Exit(0) ve else-if bloğu kaldırıldı.
		if secrets {
			if zsh {
				if _, err := os.Stat(zshHistoryFile); err == nil {
					color.Cyan("===============================================================")
					color.Cyan("Zsh secret scan is started.")
					color.Cyan("===============================================================")
					util.ProcessZshHistoryFileRegex(zshHistoryFile)
					color.Cyan("===============================================================")
					color.Cyan("Zsh secret scan is finished.")
					color.Cyan("===============================================================")
				} else {
					color.Yellow("Zsh history file not found: %s\n", zshHistoryFile)
				}
			}

			if bash {
				if _, err := os.Stat(bashHistoryFile); err == nil {
					color.Cyan("===============================================================")
					color.Cyan("Bash secret scan is started.")
					color.Cyan("===============================================================")
					util.ProcessBashHistoryFileRegex(bashHistoryFile)
					color.Cyan("===============================================================")
					color.Cyan("Bash secret scan is finished.")
					color.Cyan("===============================================================")
				} else {
					color.Yellow("Bash history file not found: %s\n", bashHistoryFile)
				}
			}

			if fish {
				if _, err := os.Stat(fishHistoryFile); err == nil {
					color.Cyan("===============================================================")
					color.Cyan("Fish secret scan is started.")
					color.Cyan("===============================================================")
					util.ProcessFishHistoryFileRegex(fishHistoryFile)
					color.Cyan("===============================================================")
					color.Cyan("Fish secret scan is finished.")
					color.Cyan("===============================================================")
				} else {
					color.Yellow("Fish history file not found: %s\n", fishHistoryFile)
				}
			}
			return
		}

		if zsh {
			if _, err := os.Stat(zshrcFile); err == nil {
				util.IsAliasInConfigFile(zshrcFile)
			}

			if _, err := os.Stat(zshHistoryFile); err == nil {
				color.Cyan("===============================================================")
				color.Cyan("Zsh scan is started.")
				color.Cyan("===============================================================")
				util.ProcessZshHistoryFile(zshHistoryFile)
				color.Cyan("===============================================================")
				color.Cyan("Zsh scan is finished.")
				color.Cyan("===============================================================")
			} else {
				color.Yellow("Zsh history file not found: %s\n", zshHistoryFile)
			}
		}

		if bash {
			if _, err := os.Stat(bashrcFile); err == nil {
				util.IsAliasInConfigFile(bashrcFile)
			}

			if _, err := os.Stat(bashHistoryFile); err == nil {
				color.Cyan("===============================================================")
				color.Cyan("Bash scan is started.")
				color.Cyan("===============================================================")
				util.ProcessBashHistoryFile(bashHistoryFile)
				color.Cyan("===============================================================")
				color.Cyan("Bash scan is finished.")
				color.Cyan("===============================================================")
			} else {
				color.Yellow("Bash history file not found: %s\n", bashHistoryFile)
			}
		}

		if fish {
			if _, err := os.Stat(fishConfigFile); err == nil {
				util.IsAliasInConfigFile(fishConfigFile)
			}

			if _, err := os.Stat(fishHistoryFile); err == nil {
				color.Cyan("===============================================================")
				color.Cyan("Fish scan is started.")
				color.Cyan("===============================================================")
				util.ProcessFishHistoryFile(fishHistoryFile)
				color.Cyan("===============================================================")
				color.Cyan("Fish scan is finished.")
				color.Cyan("===============================================================")
			} else {
				color.Yellow("Fish history file not found: %s\n", fishHistoryFile)
			}
		}
	},
}

func init() {
	extractCmd.Flags().BoolP("zsh", "z", false, "Check passwords on ZSH")
	extractCmd.Flags().BoolP("bash", "b", false, "Check passwords on BASH")
	extractCmd.Flags().BoolP("fish", "f", false, "Check passwords on FISH")
	extractCmd.Flags().BoolP("secrets", "s", false, "Check secrets on shell history")
	extractCmd.Flags().BoolP("all", "a", false, "Check passwords on all shells")
	extractCmd.Flags().BoolP("redact", "r", false, "Mask detected secrets in terminal output")

	rootCmd.AddCommand(extractCmd)
}
