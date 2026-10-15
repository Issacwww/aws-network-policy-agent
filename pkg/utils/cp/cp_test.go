package cp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstallBPFBinaries_DNSEgressBinaryReplacesEgressBinary(t *testing.T) {
	imageDir := t.TempDir()
	hostDir := t.TempDir() + "/"
	require.NoError(t, os.WriteFile(filepath.Join(imageDir, TC_DNS_EGRESS_BINARY), []byte("dns egress"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(hostDir, TC_EGRESS_BINARY), []byte("egress"), 0o644))
	t.Chdir(imageDir)

	assert.NoError(t, InstallBPFBinaries([]string{TC_DNS_EGRESS_BINARY}, hostDir))

	installed, err := os.ReadFile(filepath.Join(hostDir, TC_EGRESS_BINARY))
	require.NoError(t, err)
	assert.Equal(t, "dns egress", string(installed))
	_, err = os.Stat(filepath.Join(hostDir, TC_DNS_EGRESS_BINARY))
	assert.True(t, os.IsNotExist(err), "the DNS egress binary is installed only under the egress binary name")
}
