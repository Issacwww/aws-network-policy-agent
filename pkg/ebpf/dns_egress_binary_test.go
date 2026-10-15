package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-ebpf-sdk-go/pkg/tc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostBinaryName(t *testing.T) {
	assert.Equal(t, TC_EGRESS_BINARY, hostBinaryName(TC_DNS_EGRESS_BINARY))
	assert.Equal(t, TC_EGRESS_BINARY, hostBinaryName(TC_EGRESS_BINARY))
	assert.Equal(t, TC_INGRESS_BINARY, hostBinaryName(TC_INGRESS_BINARY))
	assert.Equal(t, TC_V6_EGRESS_BINARY, hostBinaryName(TC_V6_EGRESS_BINARY))
}

// The DNS policy egress binary is compared against the host copy of the regular egress binary, so
// turning DNS policy on or off reloads the egress probes, and a restart with the same setting does not.
func TestCheckAndUpdateBPFBinaries_DNSEgressBinary(t *testing.T) {
	tests := []struct {
		name             string
		imageBinary      string
		imageContent     string
		hostEgressBinary string
		wantEgressUpdate bool
	}{
		{
			name:             "DNS policy turned on",
			imageBinary:      TC_DNS_EGRESS_BINARY,
			imageContent:     "dns egress",
			hostEgressBinary: "egress",
			wantEgressUpdate: true,
		},
		{
			name:             "DNS policy stays on",
			imageBinary:      TC_DNS_EGRESS_BINARY,
			imageContent:     "dns egress",
			hostEgressBinary: "dns egress",
			wantEgressUpdate: false,
		},
		{
			name:             "DNS policy turned off",
			imageBinary:      TC_EGRESS_BINARY,
			imageContent:     "egress",
			hostEgressBinary: "dns egress",
			wantEgressUpdate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageDir := t.TempDir()
			hostDir := t.TempDir() + "/"
			require.NoError(t, os.WriteFile(filepath.Join(imageDir, tt.imageBinary), []byte(tt.imageContent), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(hostDir, TC_EGRESS_BINARY), []byte(tt.hostEgressBinary), 0o644))
			t.Chdir(imageDir)

			updateIngress, updateEgress, updateEvents, err := checkAndUpdateBPFBinaries(tc.New([]string{POD_VETH_PREFIX}),
				[]string{tt.imageBinary}, hostDir)
			assert.NoError(t, err)
			assert.False(t, updateIngress)
			assert.Equal(t, tt.wantEgressUpdate, updateEgress)
			assert.False(t, updateEvents)
		})
	}
}
