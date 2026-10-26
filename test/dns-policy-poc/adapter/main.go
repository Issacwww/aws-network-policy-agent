// Kind-only substitute for EC2 metadata and the VPC CNI config/lifecycle RPCs.
// It does not implement policy selection, DNS authorization, or packet enforcement.
package main

import (
	"context"
	"fmt"
	rpc "github.com/aws/amazon-vpc-cni-k8s/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

type config struct {
	rpc.UnimplementedConfigServerBackendServer
}

func (config) GetNetworkPolicyConfigs(context.Context, *emptypb.Empty) (*rpc.NetworkPolicyAgentConfigReply, error) {
	return &rpc.NetworkPolicyAgentConfigReply{NetworkPolicyMode: "standard"}, nil
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "enforce" {
		if len(os.Args) != 4 {
			log.Fatal("enforce POD NAMESPACE")
		}
		c, e := grpc.NewClient("unix:///var/run/aws-node/npa.sock", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if e != nil {
			log.Fatal(e)
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, e := rpc.NewNPBackendClient(c).EnforceNpToPod(ctx, &rpc.EnforceNpRequest{K8S_POD_NAME: os.Args[2], K8S_POD_NAMESPACE: os.Args[3], NETWORK_POLICY_MODE: "standard", InterfaceCount: 1})
		if e != nil || !r.GetSuccess() {
			log.Fatalf("enforce: %v %v", r, e)
		}
		return
	}
	os.MkdirAll("/var/run/aws-node", 0755)
	os.Remove("/var/run/aws-node/ipamd.sock")
	ln, e := net.Listen("unix", "/var/run/aws-node/ipamd.sock")
	if e != nil {
		log.Fatal(e)
	}
	g := grpc.NewServer()
	rpc.RegisterConfigServerBackendServer(g, config{})
	go func() { log.Fatal(g.Serve(ln)) }()
	http.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "kind-test-token") })
	http.HandleFunc("/latest/meta-data/local-ipv4", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, os.Getenv("NODE_IP")) })
	log.Fatal(http.ListenAndServe("127.0.0.1:18080", nil))
}
