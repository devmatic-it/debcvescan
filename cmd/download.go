package cmd

import (
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

// initializes arguments for pkg commmand
func init() {
	rootCmd.AddCommand(downloadCmd)

}

// download command
var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download json",
	Long:  `Download cve json file.`,
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		client := &http.Client{}
		req, err := http.NewRequest("GET", "https://security-tracker.debian.org/tracker/data/json", nil)
		if err != nil {
			panic(err)
		}

		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}

		defer resp.Body.Close()

		json, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		err = os.WriteFile("./debcvelist.json", json, 0600)
		if err != nil {
			panic(err)
		}

	},
}
