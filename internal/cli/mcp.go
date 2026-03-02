package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/go-siros-cli/internal/daemon/ipc"
	"github.com/sirosfoundation/go-siros-cli/pkg/mcp"
)

var (
	mcpSocketPath string
)

// mcpCmd represents the MCP server command.
var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run an MCP (Model Context Protocol) server",
	Long: `Run an MCP server that allows AI assistants to interact with the wallet.

The MCP server communicates via JSON-RPC 2.0 over stdio, allowing integration
with AI assistants like Claude, ChatGPT, and others that support the Model
Context Protocol.

The server connects to the wallet daemon for key operations. Make sure the
daemon is running with 'wallet-cli daemon start' before using MCP tools
that require wallet access.

Available MCP tools:
  - wallet_status: Get wallet daemon status
  - wallet_list_keys: List available keys
  - wallet_lock: Lock the wallet
  - wallet_sign_jwt: Sign a JWT using a wallet key

Example usage in Claude Desktop config (claude_desktop_config.json):
  {
    "mcpServers": {
      "wallet": {
        "command": "/path/to/wallet-cli",
        "args": ["mcp"]
      }
    }
  }`,
	RunE: runMCP,
}

func init() {
	rootCmd.AddCommand(mcpCmd)

	mcpCmd.Flags().StringVar(&mcpSocketPath, "socket", "", "daemon socket path (default: platform-specific)")
}

func runMCP(cmd *cobra.Command, args []string) error {
	socketPath := mcpSocketPath
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}

	// Create MCP server
	server, err := mcp.NewServer(&mcp.ServerConfig{
		SocketPath: socketPath,
		Input:      os.Stdin,
		Output:     os.Stdout,
	})
	if err != nil {
		return fmt.Errorf("failed to create MCP server: %w", err)
	}

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		server.Shutdown()
	}()

	// Run the server
	return server.Run()
}
