package clusternetworkpolicy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	policyv1alpha1 "github.com/aws/amazon-network-policy-controller-k8s/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	frameworkutils "github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	s2DNSNamespace = "dns-policy-s2"
	s2PodTimeout   = 2 * time.Minute
	s2ListenerPort = 50052
)

var _ = Describe("S2 DNS policy behavior contract", Ordered, ContinueOnFailure, func() {
	var (
		serverDeployment  *appsv1.Deployment
		selectedPod       *v1.Pod
		unselectedPod     *v1.Pod
		noMatchService    *v1.Service
		cpeService        *v1.Service
		peService         *v1.Service
		modifiedService   *v1.Service
		dnsAllowPolicy    *unstructured.Unstructured
		cpeDomainPolicy   *unstructured.Unstructured
		applicationPolicy *policyv1alpha1.ApplicationNetworkPolicy
		selectedDenyAll   *networking.NetworkPolicy
		cleanupPolicy     *unstructured.Unstructured
		cleanupDenyAll    *networking.NetworkPolicy
	)

	serviceDomain := func(service *v1.Service) string {
		return service.Name + "." + s2DNSNamespace + ".svc.cluster.local"
	}

	httpURL := func(host string, ports ...int32) string {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			host = "[" + host + "]"
		}
		port := int32(8080)
		if len(ports) > 0 {
			port = ports[0]
		}
		return "http://" + host + ":" + strconv.Itoa(int(port))
	}

	BeforeAll(func() {
		Expect(fw.NamespaceManager.CreateNamespace(ctx, s2DNSNamespace)).To(Succeed())
		namespace := &v1.Namespace{}
		Expect(fw.K8sClient.Get(ctx, client.ObjectKey{Name: s2DNSNamespace}, namespace)).To(Succeed())
		namespace.Labels = map[string]string{"test": "dns-policy-s2"}
		Expect(fw.K8sClient.Update(ctx, namespace)).To(Succeed())

		serverContainer := manifest.NewBusyBoxContainerBuilder().
			ImageRepository(fw.Options.TestImageRegistry).
			Command([]string{"/bin/sh", "-c"}).
			Args([]string{`while true; do printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok' | nc -l -p 8080; done`}).
			Build()
		serverDeployment = manifest.NewDefaultDeploymentBuilder().
			Namespace(s2DNSNamespace).
			Name("s2-dns-server").
			Replicas(1).
			AddLabel("app", "s2-dns-server").
			Container(serverContainer).
			Build()
		var err error
		serverDeployment, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, serverDeployment)
		Expect(err).ToNot(HaveOccurred())

		createService := func(name string, port int32) *v1.Service {
			service := manifest.NewHTTPService().
				Namespace(s2DNSNamespace).
				Name(name).
				Port(port).
				Selector("app", "s2-dns-server").
				Build()
			service.Spec.Ports[0].TargetPort = intstr.FromInt32(8080)
			created, createErr := fw.ServiceManager.CreateService(ctx, service)
			Expect(createErr).ToNot(HaveOccurred())
			return created
		}
		noMatchService = createService("s2-no-match", 8080)
		cpeService = createService("s2-cpe-domain", 8080)
		peService = createService("s2-pe-domain", 8080)
		modifiedService = createService("s2-modified-domain", 8081)

		selectedPod = manifest.NewDefaultPodBuilder().
			Namespace(s2DNSNamespace).
			Name("s2-selected-client").
			AddLabel("app", "s2-selected-client").
			Container(manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"sleep", "3600"}).
				Build()).
			Build()
		selectedPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, selectedPod, s2PodTimeout)
		Expect(err).ToNot(HaveOccurred())

		unselectedPod = manifest.NewDefaultPodBuilder().
			Namespace(s2DNSNamespace).
			Name("s2-unselected-client").
			AddLabel("app", "s2-unselected-client").
			Container(manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"sleep", "3600"}).
				Build()).
			Build()
		unselectedPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, unselectedPod, s2PodTimeout)
		Expect(err).ToNot(HaveOccurred())

		dnsRuleBuilder := manifest.NewClusterEgressRuleBuilder().
			Name("s2-allow-dns").
			Action("Accept").
			AddPort(53, "UDP").
			AddPort(53, "TCP")
		var dnsRule map[string]interface{}
		if fw.Options.IsAutoCluster {
			dnsRule = dnsRuleBuilder.BuildEgressRule([]map[string]interface{}{
				manifest.NewNetworksPeer([]string{dnsCIDRAddress}),
			})
		} else {
			dnsRule = dnsRuleBuilder.BuildEgressRule([]map[string]interface{}{
				manifest.NewPodsPeer(
					map[string]string{"kubernetes.io/metadata.name": "kube-system"},
					map[string]string{"k8s-app": "kube-dns"},
				),
			})
		}
		dnsAllowPolicy = manifest.NewClusterNetworkPolicyBuilder().
			Name("s2-explicit-dns-allow").
			Priority(5).
			Tier("Admin").
			SubjectNamespaces(map[string]string{"test": "dns-policy-s2"}).
			AddEgressRule(dnsRule).
			Build()
		Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, dnsAllowPolicy)).To(Succeed())

		cpeDomainRule := manifest.NewClusterEgressRuleBuilder().
			Name("s2-cpe-domain").
			Action("Accept").
			AddPort(8080, "TCP").
			BuildEgressRule([]map[string]interface{}{
				manifest.NewDomainNamesPeer([]string{serviceDomain(cpeService)}),
			})
		cpeDomainPolicy = manifest.NewClusterNetworkPolicyBuilder().
			Name("s2-cpe-domain").
			Priority(50).
			Tier("Admin").
			SubjectPods(
				map[string]string{"test": "dns-policy-s2"},
				map[string]string{"app": "s2-selected-client"},
			).
			AddEgressRule(cpeDomainRule).
			Build()
		Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, cpeDomainPolicy)).To(Succeed())

		applicationPolicy = s2ApplicationNetworkPolicy(
			"s2-pe-domain", "s2-selected-client", serviceDomain(peService),
		)
		Expect(fw.K8sClient.Create(ctx, applicationPolicy)).To(Succeed())

		selectedDenyAll = manifest.NewNetworkPolicyBuilder().
			Namespace(s2DNSNamespace).
			Name("s2-selected-deny-all").
			PodSelector("app", "s2-selected-client").
			SetPolicyTypes([]networking.PolicyType{networking.PolicyTypeEgress}).
			Build()
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, selectedDenyAll)).To(Succeed())
	})

	It("forwards a no-match DNS response without authorizing the returned address", func() {
		domain := serviceDomain(noMatchService)
		Eventually(func() error {
			_, err := fw.PodManager.ExecInPod(s2DNSNamespace, selectedPod.Name, []string{"nslookup", domain})
			return err
		}, time.Minute, 2*time.Second).Should(Succeed())

		Consistently(func() error {
			_, err := fw.PodManager.ExecInPod(s2DNSNamespace, selectedPod.Name,
				[]string{"wget", "-qO-", "-T", "3", httpURL(noMatchService.Spec.ClusterIP)})
			return err
		}, 10*time.Second, 2*time.Second).Should(HaveOccurred())

		Consistently(func() error {
			_, err := fw.PodManager.ExecInPod(s2DNSNamespace, selectedPod.Name,
				[]string{"wget", "-qO-", "-T", "3", httpURL(domain)})
			return err
		}, 10*time.Second, 2*time.Second).Should(HaveOccurred())
	})

	It("forwards an unknown source without mutating a selected pod's authorization", func() {
		domain := serviceDomain(cpeService)
		checkPod := s2UnknownSourcePod(selectedPod.Spec.NodeName, fw.Options.TestImageRegistry)
		checkPod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, s2PodTimeout)
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)).To(Succeed())
		})

		response, err := fw.PodManager.ExecInPod(s2DNSNamespace, checkPod.Name,
			[]string{"/bin/sh", "-c", s2RawDNSQueryCommand(domain)})
		Expect(err).ToNot(HaveOccurred())
		responseBytes := strings.Fields(response)
		Expect(len(responseBytes)).To(BeNumerically(">", 4))
		Expect(responseBytes[:2]).To(Equal([]string{"12", "34"}))
		flagsHigh, parseErr := strconv.ParseUint(responseBytes[2], 16, 8)
		Expect(parseErr).ToNot(HaveOccurred())
		flagsLow, parseErr := strconv.ParseUint(responseBytes[3], 16, 8)
		Expect(parseErr).ToNot(HaveOccurred())
		Expect(flagsHigh&0x80).To(Equal(uint64(0x80)), "listener response must set the DNS QR bit")
		Expect(flagsLow&0x0f).To(Equal(uint64(0)), "listener response must have DNS RCODE 0")
		Expect(strings.Join(responseBytes, " ")).To(ContainSubstring(s2AddressHex(cpeService.Spec.ClusterIP)))

		Consistently(func() error {
			_, execErr := fw.PodManager.ExecInPod(s2DNSNamespace, selectedPod.Name,
				[]string{"wget", "-qO-", "-T", "3", httpURL(cpeService.Spec.ClusterIP)})
			return execErr
		}, 10*time.Second, 2*time.Second).Should(HaveOccurred(),
			"an unknown source must not populate another pod's ipcache")
	})

	It("leaves an unselected pod outside DNS redirection", func() {
		domain := serviceDomain(noMatchService)
		Eventually(func() error {
			_, err := fw.PodManager.ExecInPod(s2DNSNamespace, unselectedPod.Name, []string{"nslookup", domain})
			return err
		}, time.Minute, 2*time.Second).Should(Succeed())
		Eventually(func() (string, error) {
			return fw.PodManager.ExecInPod(s2DNSNamespace, unselectedPod.Name,
				[]string{"wget", "-qO-", "-T", "3", httpURL(domain)})
		}, time.Minute, 2*time.Second).Should(Equal("ok"))

		checkPod := frameworkutils.BuildBPFCheckPod("kube-system", unselectedPod.Spec.NodeName)
		checkPod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, s2PodTimeout)
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)).To(Succeed())
		})

		veth, err := s2HostVeth(checkPod, unselectedPod.Status.PodIP)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() (int, error) {
			return s2DNSRedirectRuleCount(checkPod, veth)
		}, 30*time.Second, 2*time.Second).Should(Equal(0))

	})

	It("recomputes PE and CPE sources through modify and delete lifecycle", func() {
		cpeDomain := serviceDomain(cpeService)
		Eventually(func() (string, error) {
			return fw.PodManager.ExecInPod(s2DNSNamespace, selectedPod.Name,
				[]string{"wget", "-qO-", "-T", "3", httpURL(cpeDomain)})
		}, time.Minute, 2*time.Second).Should(Equal("ok"))

		checkPod := frameworkutils.BuildBPFCheckPod("kube-system", selectedPod.Spec.NodeName)
		checkPod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, s2PodTimeout)
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)).To(Succeed())
		})
		veth, err := s2HostVeth(checkPod, selectedPod.Status.PodIP)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() (int, error) {
			return s2DNSRedirectRuleCount(checkPod, veth)
		}, time.Minute, 2*time.Second).Should(Equal(2))

		Expect(fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, cpeDomainPolicy)).To(Succeed())
		cpeDomainPolicy = nil
		Eventually(func() bool {
			return s2ClusterPolicyEndpointExists("s2-cpe-domain", selectedPod.Name)
		}, time.Minute, 2*time.Second).Should(BeFalse())

		peDomain := serviceDomain(peService)
		Eventually(func() (string, error) {
			return fw.PodManager.ExecInPod(s2DNSNamespace, selectedPod.Name,
				[]string{"wget", "-qO-", "-T", "3", httpURL(peDomain)})
		}, time.Minute, 2*time.Second).Should(Equal("ok"))
		Consistently(func() (int, error) {
			return s2DNSRedirectRuleCount(checkPod, veth)
		}, 10*time.Second, 2*time.Second).Should(Equal(2))

		currentPolicy := &policyv1alpha1.ApplicationNetworkPolicy{}
		Expect(fw.K8sClient.Get(ctx, client.ObjectKey{
			Name: applicationPolicy.Name, Namespace: applicationPolicy.Namespace,
		}, currentPolicy)).To(Succeed())
		currentPolicy.Spec.Egress[0].To[0].DomainNames = []policyv1alpha1.DomainName{
			policyv1alpha1.DomainName(serviceDomain(modifiedService)),
		}
		modifiedPort := intstr.FromInt32(8081)
		currentPolicy.Spec.Egress[0].Ports[0].Port = &modifiedPort
		Expect(fw.K8sClient.Update(ctx, currentPolicy)).To(Succeed())
		applicationPolicy = currentPolicy

		Eventually(func() ([]string, error) {
			return s2PolicyEndpointDomainRules(applicationPolicy.Name, selectedPod.Name)
		}, time.Minute, 2*time.Second).Should(Equal([]string{
			serviceDomain(modifiedService) + "|TCP|8081|0",
		}))
		Eventually(func() (string, error) {
			return fw.PodManager.ExecInPod(s2DNSNamespace, selectedPod.Name,
				[]string{"wget", "-qO-", "-T", "3", httpURL(serviceDomain(modifiedService), 8081)})
		}, time.Minute, 2*time.Second).Should(Equal("ok"))

		Expect(fw.K8sClient.Delete(ctx, applicationPolicy)).To(Succeed())
		applicationPolicy = nil
		Eventually(func() ([]string, error) {
			return s2PolicyEndpointDomainRules("s2-pe-domain", selectedPod.Name)
		}, time.Minute, 2*time.Second).Should(BeEmpty())
		Eventually(func() (int, error) {
			return s2DNSRedirectRuleCount(checkPod, veth)
		}, time.Minute, 2*time.Second).Should(Equal(0))
	})

	It("removes deleted-pod redirect and ipcache state without re-adding it", func() {
		cleanupPod := manifest.NewDefaultPodBuilder().
			Namespace(s2DNSNamespace).
			Name("s2-cleanup-client").
			AddLabel("app", "s2-cleanup-client").
			Container(manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"sleep", "3600"}).
				Build()).
			Build()
		var err error
		cleanupPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, cleanupPod, s2PodTimeout)
		Expect(err).ToNot(HaveOccurred())

		cleanupRule := manifest.NewClusterEgressRuleBuilder().
			Name("s2-cleanup-domain").
			Action("Accept").
			AddPort(8080, "TCP").
			BuildEgressRule([]map[string]interface{}{
				manifest.NewDomainNamesPeer([]string{serviceDomain(cpeService)}),
			})
		cleanupPolicy = manifest.NewClusterNetworkPolicyBuilder().
			Name("s2-cleanup-domain").
			Priority(50).
			Tier("Admin").
			SubjectPods(
				map[string]string{"test": "dns-policy-s2"},
				map[string]string{"app": "s2-cleanup-client"},
			).
			AddEgressRule(cleanupRule).
			Build()
		Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, cleanupPolicy)).To(Succeed())

		cleanupDenyAll = manifest.NewNetworkPolicyBuilder().
			Namespace(s2DNSNamespace).
			Name("s2-cleanup-deny-all").
			PodSelector("app", "s2-cleanup-client").
			SetPolicyTypes([]networking.PolicyType{networking.PolicyTypeEgress}).
			Build()
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, cleanupDenyAll)).To(Succeed())

		Eventually(func() (string, error) {
			return fw.PodManager.ExecInPod(s2DNSNamespace, cleanupPod.Name,
				[]string{"wget", "-qO-", "-T", "3", httpURL(serviceDomain(cpeService))})
		}, time.Minute, 2*time.Second).Should(Equal("ok"))

		checkPod := frameworkutils.BuildBPFCheckPod("kube-system", cleanupPod.Spec.NodeName)
		checkPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, s2PodTimeout)
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)).To(Succeed())
		})
		veth, err := s2HostVeth(checkPod, cleanupPod.Status.PodIP)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() (int, error) {
			return s2DNSRedirectRuleCount(checkPod, veth)
		}, time.Minute, 2*time.Second).Should(Equal(2))

		ipcachePath := utils.GetIPCacheBPFMapPinPathFromPodIdentifier(
			utils.GetPodIdentifier(cleanupPod.Name, cleanupPod.Namespace),
		)
		Eventually(func() (bool, error) {
			return s2HostPathExists(checkPod, ipcachePath)
		}, time.Minute, 2*time.Second).Should(BeTrue())

		Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, cleanupPod)).To(Succeed())
		Eventually(func() (int, error) {
			return s2DNSRedirectRuleCount(checkPod, veth)
		}, time.Minute, 2*time.Second).Should(Equal(0))
		Eventually(func() (bool, error) {
			return s2HostPathExists(checkPod, ipcachePath)
		}, time.Minute, 2*time.Second).Should(BeFalse())

		Consistently(func() bool {
			ruleCount, ruleErr := s2DNSRedirectRuleCount(checkPod, veth)
			mapExists, mapErr := s2HostPathExists(checkPod, ipcachePath)
			return ruleErr == nil && mapErr == nil && ruleCount == 0 && !mapExists
		}, 10*time.Second, 2*time.Second).Should(BeTrue())
	})

	AfterAll(func() {
		var cleanupErrors []error
		recordCleanupError := func(operation string, err error) {
			if err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("%s: %w", operation, err))
			}
		}
		if cleanupPolicy != nil {
			recordCleanupError(
				"delete cleanup ClusterNetworkPolicy",
				fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, cleanupPolicy),
			)
		}
		if cpeDomainPolicy != nil {
			recordCleanupError(
				"delete CPE domain ClusterNetworkPolicy",
				fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, cpeDomainPolicy),
			)
		}
		if dnsAllowPolicy != nil {
			recordCleanupError(
				"delete DNS allow ClusterNetworkPolicy",
				fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, dnsAllowPolicy),
			)
		}
		if applicationPolicy != nil {
			recordCleanupError(
				"delete ApplicationNetworkPolicy",
				client.IgnoreNotFound(fw.K8sClient.Delete(ctx, applicationPolicy)),
			)
		}
		if selectedDenyAll != nil {
			recordCleanupError(
				"delete selected-pod NetworkPolicy",
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, selectedDenyAll),
			)
		}
		if cleanupDenyAll != nil {
			recordCleanupError(
				"delete cleanup NetworkPolicy",
				fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, cleanupDenyAll),
			)
		}
		if selectedPod != nil {
			recordCleanupError(
				"delete selected client pod",
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, selectedPod),
			)
		}
		if unselectedPod != nil {
			recordCleanupError(
				"delete unselected client pod",
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, unselectedPod),
			)
		}
		for _, service := range []*v1.Service{noMatchService, cpeService, peService, modifiedService} {
			if service != nil {
				recordCleanupError(
					"delete service "+service.Name,
					fw.ServiceManager.DeleteService(ctx, service),
				)
			}
		}
		if serverDeployment != nil {
			recordCleanupError(
				"delete server deployment",
				fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, serverDeployment),
			)
		}
		recordCleanupError(
			"delete S2 namespace",
			fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, s2DNSNamespace),
		)
		Expect(errors.Join(cleanupErrors...)).ToNot(HaveOccurred())
	})
})

func s2ApplicationNetworkPolicy(name, app, domain string) *policyv1alpha1.ApplicationNetworkPolicy {
	protocol := v1.ProtocolTCP
	port := intstr.FromInt32(8080)
	return &policyv1alpha1.ApplicationNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s2DNSNamespace},
		Spec: policyv1alpha1.ApplicationNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": app}},
			PolicyTypes: []networking.PolicyType{networking.PolicyTypeEgress},
			Egress: []policyv1alpha1.ApplicationNetworkPolicyEgressRule{{
				Ports: []networking.NetworkPolicyPort{{Protocol: &protocol, Port: &port}},
				To: []policyv1alpha1.ApplicationNetworkPolicyPeer{{
					DomainNames: []policyv1alpha1.DomainName{policyv1alpha1.DomainName(domain)},
				}},
			}},
		},
	}
}

func s2UnknownSourcePod(nodeName, imageRegistry string) *v1.Pod {
	pod := manifest.NewDefaultPodBuilder().
		Namespace(s2DNSNamespace).
		Name("s2-unknown-source").
		Container(manifest.NewBusyBoxContainerBuilder().
			ImageRepository(imageRegistry).
			Command([]string{"sleep", "300"}).
			Build()).
		Build()
	pod.Spec.NodeName = nodeName
	pod.Spec.HostNetwork = true
	pod.Spec.DNSPolicy = v1.DNSClusterFirstWithHostNet
	return pod
}

func s2RawDNSQueryCommand(domain string) string {
	packet := []byte{
		0x12, 0x34, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0x00)
	queryType := uint16(1)
	if fw.Options.IpFamily == "IPv6" {
		queryType = 28
	}
	packet = append(packet, byte(queryType>>8), byte(queryType), 0x00, 0x01)
	var escaped strings.Builder
	for _, value := range packet {
		fmt.Fprintf(&escaped, `\%03o`, value)
	}
	return fmt.Sprintf(
		`printf '%s' | nc -u -w 3 %s %d | od -An -tx1`,
		escaped.String(),
		s2ListenerAddress(),
		s2ListenerPort,
	)
}

func s2ListenerAddress() string {
	if fw.Options.IpFamily == "IPv6" {
		return "fd00::53"
	}
	return "169.254.20.10"
}

func s2AddressHex(address string) string {
	ip := net.ParseIP(address)
	if ip == nil {
		return ""
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	} else {
		ip = ip.To16()
	}
	encoded := make([]string, len(ip))
	for index := range ip {
		encoded[index] = fmt.Sprintf("%02x", ip[index])
	}
	return strings.Join(encoded, " ")
}

func s2HostVeth(checkPod *v1.Pod, podIP string) (string, error) {
	out, err := fw.PodManager.ExecInPod(checkPod.Namespace, checkPod.Name, []string{
		"chroot", "/host", "/bin/sh", "-c",
		`ip -o route get "$1" | sed -n 's/.* dev \([^ ]*\).*/\1/p'`,
		"sh", podIP,
	})
	if err != nil {
		return "", err
	}
	veth := strings.TrimSpace(out)
	if veth == "" {
		return "", fmt.Errorf("host route for pod IP %s did not identify a veth", podIP)
	}
	return veth, nil
}

func s2DNSRedirectRuleCount(checkPod *v1.Pod, veth string) (int, error) {
	tableFamily := "ip"
	if fw.Options.IpFamily == "IPv6" {
		tableFamily = "ip6"
	}
	out, err := fw.PodManager.ExecInPod(checkPod.Namespace, checkPod.Name, []string{
		"chroot", "/host", "/bin/sh", "-c",
		`nft_output=$(nft -nn list table "$1" dns_redirect) || exit $?; printf '%s\n' "$nft_output" | grep -F "$2" | wc -l`,
		"sh", tableFamily, veth,
	})
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out))
}

func s2HostPathExists(checkPod *v1.Pod, hostPath string) (bool, error) {
	_, err := fw.PodManager.ExecInPod(checkPod.Namespace, checkPod.Name, []string{
		"/bin/sh", "-c", `test -e "/host$1"`, "sh", hostPath,
	})
	if err == nil {
		return true, nil
	}
	if strings.Contains(err.Error(), "exit code 1") {
		return false, nil
	}
	return false, err
}

func s2PolicyEndpointDomainRules(policyName, podName string) ([]string, error) {
	policyEndpoints := &policyv1alpha1.PolicyEndpointList{}
	if err := fw.K8sClient.List(ctx, policyEndpoints, client.InNamespace(s2DNSNamespace)); err != nil {
		return nil, err
	}
	var domainRules []string
	for _, endpoint := range policyEndpoints.Items {
		if endpoint.Spec.PolicyRef.Name != policyName || !s2EndpointContainsPod(endpoint.Spec.PodSelectorEndpoints, podName) {
			continue
		}
		for _, egress := range endpoint.Spec.Egress {
			if egress.DomainName == "" {
				continue
			}
			if len(egress.Ports) == 0 {
				domainRules = append(domainRules, string(egress.DomainName)+"|ANY|0|0")
				continue
			}
			for _, port := range egress.Ports {
				protocol := "nil"
				if port.Protocol != nil {
					protocol = string(*port.Protocol)
				}
				startPort := int32(0)
				if port.Port != nil {
					startPort = *port.Port
				}
				endPort := int32(0)
				if port.EndPort != nil {
					endPort = *port.EndPort
				}
				domainRules = append(domainRules, fmt.Sprintf(
					"%s|%s|%d|%d",
					egress.DomainName,
					protocol,
					startPort,
					endPort,
				))
			}
		}
	}
	return domainRules, nil
}

func s2ClusterPolicyEndpointExists(policyName, podName string) bool {
	endpoints := &policyv1alpha1.ClusterPolicyEndpointList{}
	if err := fw.K8sClient.List(ctx, endpoints); err != nil {
		return true
	}
	for _, endpoint := range endpoints.Items {
		if endpoint.Spec.PolicyRef.Name == policyName &&
			s2EndpointContainsPod(endpoint.Spec.PodSelectorEndpoints, podName) {
			return true
		}
	}
	return false
}

func s2EndpointContainsPod(endpoints []policyv1alpha1.PodEndpoint, podName string) bool {
	for _, endpoint := range endpoints {
		if endpoint.Name == podName && endpoint.Namespace == s2DNSNamespace {
			return true
		}
	}
	return false
}
