package ebpf

import (
	"os"
	"strings"
	"testing"
)

func TestIPCacheMapWriterKeepsTypedArgumentsAliveAcrossSDKCall(t *testing.T) {
	source, err := os.ReadFile("bpf_client.go")
	if err != nil {
		t.Fatalf("read bpf_client.go: %v", err)
	}
	writer := string(source)
	for _, required := range []string{
		"runtime.KeepAlive(key)",
		"runtime.KeepAlive(value)",
	} {
		if !strings.Contains(writer, required) {
			t.Errorf("BPF ipcache writer is missing %q", required)
		}
	}
}
