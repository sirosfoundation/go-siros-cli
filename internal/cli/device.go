package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirosfoundation/go-siros-cli/pkg/fido2"
	"github.com/spf13/cobra"
)

var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Manage FIDO2 devices",
	Long:  `Commands for managing and checking FIDO2/WebAuthn devices.`,
}

var deviceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List connected FIDO2 devices",
	Long:  `List all connected FIDO2/WebAuthn devices and their capabilities.`,
	RunE:  runDeviceList,
}

var deviceCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check if connected devices are compatible",
	Long: `Check if connected FIDO2 devices are compatible with this wallet.

This command checks for:
- FIDO2/CTAP2 support (U2F-only devices like YubiKey 4 are not supported)
- hmac-secret extension support (required for PRF/keystore encryption)
- Resident key (discoverable credential) support
- PIN configuration status`,
	RunE: runDeviceCheck,
}

func init() {
	deviceCmd.AddCommand(deviceListCmd)
	deviceCmd.AddCommand(deviceCheckCmd)
}

func runDeviceList(cmd *cobra.Command, args []string) error {
	provider, err := fido2.NewNativeProvider()
	if err != nil {
		return fmt.Errorf("failed to create FIDO2 provider: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	devices, err := provider.ListDevices(ctx)
	if err != nil {
		return fmt.Errorf("failed to list devices: %w", err)
	}

	if len(devices) == 0 {
		fmt.Println("No FIDO2 devices found.")
		fmt.Println("\nMake sure your security key is connected and accessible.")
		fmt.Println("On Linux, you may need to add udev rules for your device.")
		return nil
	}

	fmt.Printf("Found %d device(s):\n\n", len(devices))
	for i, dev := range devices {
		fmt.Printf("Device %d: %s\n", i+1, dev.ProductName)
		fmt.Printf("  Path:         %s\n", dev.Path)
		fmt.Printf("  Manufacturer: %s\n", dev.Manufacturer)
		fmt.Printf("  FIDO2:        %s\n", boolToYesNo(dev.IsFIDO2))

		if dev.IsFIDO2 {
			fmt.Printf("  PRF Support:  %s\n", boolToYesNo(dev.PRFSupported))
			fmt.Printf("  PIN Set:      %s\n", boolToYesNo(dev.HasPIN))

			if len(dev.Extensions) > 0 {
				fmt.Printf("  Extensions:   %s\n", strings.Join(dev.Extensions, ", "))
			}

			if len(dev.Options) > 0 {
				var opts []string
				for name, val := range dev.Options {
					if val {
						opts = append(opts, name)
					}
				}
				if len(opts) > 0 {
					fmt.Printf("  Options:      %s\n", strings.Join(opts, ", "))
				}
			}
		} else {
			fmt.Printf("  ⚠️  This device is U2F-only and NOT compatible with this wallet.\n")
		}
		fmt.Println()
	}

	return nil
}

func runDeviceCheck(cmd *cobra.Command, args []string) error {
	provider, err := fido2.NewNativeProvider()
	if err != nil {
		return fmt.Errorf("failed to create FIDO2 provider: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	devices, err := provider.ListDevices(ctx)
	if err != nil {
		return fmt.Errorf("failed to list devices: %w", err)
	}

	if len(devices) == 0 {
		fmt.Println("❌ No FIDO2 devices found.")
		fmt.Println("\nMake sure your security key is connected and accessible.")
		fmt.Println("On Linux, you may need to add udev rules for your device.")
		return nil
	}

	hasCompatible := false
	for i, dev := range devices {
		fmt.Printf("Device %d: %s (%s)\n", i+1, dev.ProductName, dev.Manufacturer)

		issues := checkDeviceCompatibility(dev)

		if len(issues) == 0 {
			fmt.Printf("  ✅ Device is fully compatible with this wallet\n")
			hasCompatible = true
		} else {
			fmt.Printf("  ❌ Device has compatibility issues:\n")
			for _, issue := range issues {
				fmt.Printf("     • %s\n", issue)
			}
		}
		fmt.Println()
	}

	if hasCompatible {
		fmt.Println("✅ You have at least one compatible device.")
	} else {
		fmt.Println("❌ No compatible devices found.")
		fmt.Println("\nThis wallet requires a FIDO2-capable security key with:")
		fmt.Println("  • FIDO2/CTAP2 support (not just U2F)")
		fmt.Println("  • hmac-secret extension (for PRF/keystore encryption)")
		fmt.Println("  • PIN configured (for user verification)")
		fmt.Println("\nRecommended devices:")
		fmt.Println("  • YubiKey 5 series (NFC, USB-A, USB-C)")
		fmt.Println("  • SoloKeys Solo 2")
		fmt.Println("  • Feitian BioPass FIDO2")
		fmt.Println("  • Google Titan Security Key (2nd generation)")
	}

	return nil
}

func checkDeviceCompatibility(dev fido2.DeviceInfo) []string {
	var issues []string

	if !dev.IsFIDO2 {
		issues = append(issues, "Device is U2F-only, not FIDO2. Upgrade to a newer security key (e.g., YubiKey 5).")
		return issues // No point checking further
	}

	if !dev.PRFSupported {
		issues = append(issues, "Device does not support hmac-secret extension (required for PRF/keystore encryption).")
	}

	// Check for resident key support
	if rkSupport, ok := dev.Options["rk"]; ok && !rkSupport {
		issues = append(issues, "Device does not support resident keys (discoverable credentials).")
	}

	// Check PIN status
	if !dev.HasPIN {
		if pinConfigurable, ok := dev.Options["clientPin"]; ok {
			if pinConfigurable {
				issues = append(issues, "Device PIN is not set. Please set a PIN using: ykman fido access change-pin (for YubiKeys) or fido2-token -S (for other devices).")
			}
		} else {
			issues = append(issues, "Device does not appear to support PIN.")
		}
	}

	return issues
}

func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
