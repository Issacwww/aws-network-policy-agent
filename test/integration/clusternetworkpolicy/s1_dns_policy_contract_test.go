package clusternetworkpolicy

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	frameworkutils "github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	s1DNSNamespace = "dns-policy-s1"
	s1PodTimeout   = 2 * time.Minute
)

var _ = Describe("S1 DNS policy cluster configuration", func() {
	It("runs with the DNS policy feature flag enabled", func() {
		daemonSet := &appsv1.DaemonSet{}
		Expect(fw.K8sClient.Get(ctx, client.ObjectKey{
			Name:      "aws-node",
			Namespace: "kube-system",
		}, daemonSet)).To(Succeed())

		var commandLine []string
		for _, container := range daemonSet.Spec.Template.Spec.Containers {
			if container.Name == "aws-eks-nodeagent" {
				commandLine = append(commandLine, container.Command...)
				commandLine = append(commandLine, container.Args...)
			}
		}
		Expect(dnsPolicyFlagEnabled(commandLine)).To(BeTrue(),
			"agent command must explicitly opt in with --enable-dns-policy=true")
	})

	It("rejects a domainNames rule whose action is Deny", func() {
		denyDomainRule := manifest.NewClusterEgressRuleBuilder().
			Name("invalid-deny-domain").
			Action("Deny").
			BuildEgressRule([]map[string]interface{}{
				manifest.NewDomainNamesPeer([]string{"api.example.com"}),
			})
		invalidPolicy := manifest.NewClusterNetworkPolicyBuilder().
			Name("s1-invalid-deny-domain").
			Priority(10).
			Tier("Admin").
			SubjectNamespaces(map[string]string{"test": "dns-policy-s1"}).
			AddEgressRule(denyDomainRule).
			Build()

		err := fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, invalidPolicy)
		if err == nil {
			defer func() {
				_ = fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, invalidPolicy)
			}()
		}
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected CEL admission Invalid error, got %v", err)
		var status apierrors.APIStatus
		Expect(errors.As(err, &status)).To(BeTrue(), "expected Kubernetes API status error")
		Expect(status.Status().Details).ToNot(BeNil(), "expected validation causes")
		var causes []string
		for _, cause := range status.Status().Details.Causes {
			causes = append(causes, cause.Field+" "+cause.Message)
		}
		causeText := strings.ToLower(strings.Join(causes, " "))
		Expect(causeText).To(ContainSubstring("domainnames"))
		Expect(causeText).To(ContainSubstring("accept"))
	})
})

var _ = Describe("S1 explicit DNS allow contract", Ordered, ContinueOnFailure, func() {
	var (
		serverDeployment *appsv1.Deployment
		serverService    *v1.Service
		priorityService  *v1.Service
		baselineService  *v1.Service
		clientPod        *v1.Pod
		baselineClient   *v1.Pod
		domainPolicy     *unstructured.Unstructured
		adminAllowPolicy *unstructured.Unstructured
		adminDenyPolicy  *unstructured.Unstructured
		baselinePolicy   *unstructured.Unstructured
		baselineDeny     *unstructured.Unstructured
		denyAllPolicy    *networking.NetworkPolicy
		baselineDenyAll  *networking.NetworkPolicy
		dnsAllowPolicy   *unstructured.Unstructured
	)

	BeforeAll(func() {
		if fw.Options.IpFamily != "IPv4" {
			Skip("S1 cluster contract is IPv4-only")
		}

		Expect(fw.NamespaceManager.CreateNamespace(ctx, s1DNSNamespace)).To(Succeed())
		namespace := &v1.Namespace{}
		Expect(fw.K8sClient.Get(ctx, client.ObjectKey{Name: s1DNSNamespace}, namespace)).To(Succeed())
		namespace.Labels = map[string]string{"test": "dns-policy-s1"}
		Expect(fw.K8sClient.Update(ctx, namespace)).To(Succeed())

		serverContainer := manifest.NewBusyBoxContainerBuilder().
			ImageRepository(fw.Options.TestImageRegistry).
			Command([]string{"/bin/sh", "-c"}).
			Args([]string{`while true; do printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok' | nc -l -p 8080; done`}).
			Build()
		serverDeployment = manifest.NewDefaultDeploymentBuilder().
			Namespace(s1DNSNamespace).
			Name("dns-server").
			Replicas(1).
			AddLabel("app", "dns-server").
			Container(serverContainer).
			Build()
		var err error
		serverDeployment, err = fw.DeploymentManager.CreateAndWaitUntilDeploymentReady(ctx, serverDeployment)
		Expect(err).ToNot(HaveOccurred())

		serverService = manifest.NewHTTPService().
			Namespace(s1DNSNamespace).
			Name("dns-server").
			Port(8080).
			Selector("app", "dns-server").
			Build()
		serverService, err = fw.ServiceManager.CreateService(ctx, serverService)
		Expect(err).ToNot(HaveOccurred())

		priorityService = manifest.NewHTTPService().
			Namespace(s1DNSNamespace).
			Name("priority-control").
			Port(8080).
			Selector("app", "dns-server").
			Build()
		priorityService, err = fw.ServiceManager.CreateService(ctx, priorityService)
		Expect(err).ToNot(HaveOccurred())

		clientPod = manifest.NewDefaultPodBuilder().
			Namespace(s1DNSNamespace).
			Name("dns-client").
			AddLabel("app", "dns-client").
			Container(manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"sleep", "3600"}).
				Build()).
			Build()
		clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, s1PodTimeout)
		Expect(err).ToNot(HaveOccurred())

		domainRule := manifest.NewClusterEgressRuleBuilder().
			Name("allow-service-domain").
			Action("Accept").
			AddPort(8080, "TCP").
			BuildEgressRule([]map[string]interface{}{
				manifest.NewDomainNamesPeer([]string{"dns-server.dns-policy-s1.svc.cluster.local"}),
			})
		domainPolicy = manifest.NewClusterNetworkPolicyBuilder().
			Name("s1-domain-allow").
			Priority(50).
			Tier("Admin").
			SubjectPods(
				map[string]string{"test": "dns-policy-s1"},
				map[string]string{"app": "dns-client"},
			).
			AddEgressRule(domainRule).
			Build()
		Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, domainPolicy)).To(Succeed())

		denyAllPolicy = manifest.NewNetworkPolicyBuilder().
			Namespace(s1DNSNamespace).
			Name("deny-all-egress").
			PodSelector("app", "dns-client").
			SetPolicyTypes([]networking.PolicyType{networking.PolicyTypeEgress}).
			Build()
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, denyAllPolicy)).To(Succeed())
	})

	It("does not make a domain rule effective before DNS is explicitly allowed", func() {
		Consistently(func() error {
			_, err := fw.PodManager.ExecInPod(s1DNSNamespace, clientPod.Name,
				[]string{"nslookup", "dns-server." + s1DNSNamespace + ".svc.cluster.local"})
			return err
		}, 10*time.Second, time.Second).Should(HaveOccurred())
	})

	It("allows the domain only after resolver traffic is explicitly allowed", func() {
		dnsRuleBuilder := manifest.NewClusterEgressRuleBuilder().
			Name("allow-dns-explicitly").
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
			Name("s1-explicit-dns-allow").
			Priority(5).
			Tier("Admin").
			SubjectNamespaces(map[string]string{"test": "dns-policy-s1"}).
			AddEgressRule(dnsRule).
			Build()
		Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, dnsAllowPolicy)).To(Succeed())

		serviceName := "dns-server." + s1DNSNamespace + ".svc.cluster.local"
		Eventually(func() error {
			_, err := fw.PodManager.ExecInPod(s1DNSNamespace, clientPod.Name, []string{"nslookup", serviceName})
			return err
		}, time.Minute, 2*time.Second).Should(Succeed())

		Eventually(func() (string, error) {
			return fw.PodManager.ExecInPod(s1DNSNamespace, clientPod.Name,
				[]string{"wget", "-qO-", "-T", "3", "http://" + serviceName + ":8080"})
		}, time.Minute, 2*time.Second).Should(Equal("ok"))
	})

	It("preserves Auto's Admin p50 domain Accept override of Admin p10 CIDR Deny", func() {
		serviceName := "dns-server." + s1DNSNamespace + ".svc.cluster.local"
		Eventually(func() (string, error) {
			return fw.PodManager.ExecInPod(s1DNSNamespace, clientPod.Name,
				[]string{"wget", "-qO-", "-T", "3", "http://" + serviceName + ":8080"})
		}, time.Minute, 2*time.Second).Should(Equal("ok"),
			"Admin p50 domain Accept must be effective before Admin p10 CIDR Deny is added")

		allowControlRule := manifest.NewClusterEgressRuleBuilder().
			Name("allow-priority-control").
			Action("Accept").
			AddPort(8080, "TCP").
			BuildEgressRule([]map[string]interface{}{
				manifest.NewNetworksPeer([]string{priorityService.Spec.ClusterIP + "/32"}),
			})
		adminAllowPolicy = manifest.NewClusterNetworkPolicyBuilder().
			Name("s1-admin-p20-cidr-allow").
			Priority(20).
			Tier("Admin").
			SubjectPods(
				map[string]string{"test": "dns-policy-s1"},
				map[string]string{"app": "dns-client"},
			).
			AddEgressRule(allowControlRule).
			Build()
		Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, adminAllowPolicy)).To(Succeed())

		controlIPURL := "http://" + priorityService.Spec.ClusterIP + ":8080"
		Eventually(func() (string, error) {
			return fw.PodManager.ExecInPod(s1DNSNamespace, clientPod.Name,
				[]string{"wget", "-qO-", "-T", "3", controlIPURL})
		}, time.Minute, 2*time.Second).Should(Equal("ok"),
			"Admin p20 CIDR Accept must authorize the synchronization destination before the p10 Deny")

		denyRule := manifest.NewClusterEgressRuleBuilder().
			Name("deny-service-ip").
			Action("Deny").
			AddPort(8080, "TCP").
			BuildEgressRule([]map[string]interface{}{
				manifest.NewNetworksPeer([]string{
					serverService.Spec.ClusterIP + "/32",
					priorityService.Spec.ClusterIP + "/32",
				}),
			})
		adminDenyPolicy = manifest.NewClusterNetworkPolicyBuilder().
			Name("s1-admin-p10-cidr-deny").
			Priority(10).
			Tier("Admin").
			SubjectPods(
				map[string]string{"test": "dns-policy-s1"},
				map[string]string{"app": "dns-client"},
			).
			AddEgressRule(denyRule).
			Build()
		Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, adminDenyPolicy)).To(Succeed())

		Eventually(func() error {
			_, err := fw.PodManager.ExecInPod(s1DNSNamespace, clientPod.Name,
				[]string{"wget", "-qO-", "-T", "3", controlIPURL})
			return err
		}, time.Minute, 2*time.Second).Should(HaveOccurred(),
			"same-pod control destination must prove the Admin p10 CIDR Deny reached the datapath")
		Consistently(func() error {
			_, err := fw.PodManager.ExecInPod(s1DNSNamespace, clientPod.Name,
				[]string{"wget", "-qO-", "-T", "3", controlIPURL})
			return err
		}, 10*time.Second, 2*time.Second).Should(HaveOccurred())

		Eventually(func() (string, error) {
			return fw.PodManager.ExecInPod(s1DNSNamespace, clientPod.Name,
				[]string{"wget", "-qO-", "-T", "3", "http://" + serviceName + ":8080"})
		}, time.Minute, 2*time.Second).Should(Equal("ok"),
			"Auto stores domain priority 50 raw and the datapath decodes it as priority 5")
		Consistently(func() (string, error) {
			return fw.PodManager.ExecInPod(s1DNSNamespace, clientPod.Name,
				[]string{"wget", "-qO-", "-T", "3", "http://" + serviceName + ":8080"})
		}, 10*time.Second, 2*time.Second).Should(Equal("ok"))
	})

	It("drops Baseline p10 domain Accept when namespace NetworkPolicy denies business traffic", func() {
		var err error
		baselineClient = manifest.NewDefaultPodBuilder().
			Namespace(s1DNSNamespace).
			Name("baseline-client").
			AddLabel("app", "baseline-client").
			Container(manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"sleep", "3600"}).
				Build()).
			Build()
		baselineClient, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, baselineClient, s1PodTimeout)
		Expect(err).ToNot(HaveOccurred())

		baselineService = manifest.NewHTTPService().
			Namespace(s1DNSNamespace).
			Name("baseline-dns-server").
			Port(8080).
			Selector("app", "dns-server").
			Build()
		baselineService, err = fw.ServiceManager.CreateService(ctx, baselineService)
		Expect(err).ToNot(HaveOccurred())

		baselineRule := manifest.NewClusterEgressRuleBuilder().
			Name("baseline-domain-allow").
			Action("Accept").
			AddPort(8080, "TCP").
			BuildEgressRule([]map[string]interface{}{
				manifest.NewDomainNamesPeer([]string{"baseline-dns-server.dns-policy-s1.svc.cluster.local"}),
			})
		baselinePolicy = manifest.NewClusterNetworkPolicyBuilder().
			Name("s1-baseline-p10-domain-allow").
			Priority(10).
			Tier("Baseline").
			SubjectPods(
				map[string]string{"test": "dns-policy-s1"},
				map[string]string{"app": "baseline-client"},
			).
			AddEgressRule(baselineRule).
			Build()
		Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, baselinePolicy)).To(Succeed())

		baselineDenyRule := manifest.NewClusterEgressRuleBuilder().
			Name("baseline-default-deny").
			Action("Deny").
			AddPort(8080, "TCP").
			BuildEgressRule([]map[string]interface{}{
				manifest.NewNetworksPeer([]string{"0.0.0.0/0"}),
			})
		baselineDeny = manifest.NewClusterNetworkPolicyBuilder().
			Name("s1-baseline-p100-cidr-deny").
			Priority(100).
			Tier("Baseline").
			SubjectPods(
				map[string]string{"test": "dns-policy-s1"},
				map[string]string{"app": "baseline-client"},
			).
			AddEgressRule(baselineDenyRule).
			Build()
		Expect(fw.ClusterNetworkPolicyManager.CreateClusterNetworkPolicy(ctx, baselineDeny)).To(Succeed())

		serviceName := "baseline-dns-server." + s1DNSNamespace + ".svc.cluster.local"
		Eventually(func() (string, error) {
			return fw.PodManager.ExecInPod(s1DNSNamespace, baselineClient.Name,
				[]string{"wget", "-qO-", "-T", "3", "http://" + serviceName + ":8080"})
		}, time.Minute, 2*time.Second).Should(Equal("ok"),
			"Baseline p10 domain Accept must be effective before namespace deny-all is added")

		serviceIPURL := "http://" + baselineService.Spec.ClusterIP + ":8080"
		Eventually(func() (string, error) {
			return fw.PodManager.ExecInPod(s1DNSNamespace, baselineClient.Name,
				[]string{"wget", "-qO-", "-T", "3", serviceIPURL})
		}, time.Minute, 2*time.Second).Should(Equal("ok"),
			"prewarmed domain ipcache must authorize a new direct-IP connection")

		baselineDenyAll = manifest.NewNetworkPolicyBuilder().
			Namespace(s1DNSNamespace).
			Name("deny-all-baseline-egress").
			PodSelector("app", "baseline-client").
			SetPolicyTypes([]networking.PolicyType{networking.PolicyTypeEgress}).
			Build()
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, baselineDenyAll)).To(Succeed())

		Eventually(func() error {
			_, err := fw.PodManager.ExecInPod(s1DNSNamespace, baselineClient.Name,
				[]string{"wget", "-qO-", "-T", "3", serviceIPURL})
			return err
		}, time.Minute, 2*time.Second).Should(HaveOccurred())
		Consistently(func() error {
			_, err := fw.PodManager.ExecInPod(s1DNSNamespace, baselineClient.Name,
				[]string{"wget", "-qO-", "-T", "3", serviceIPURL})
			return err
		}, 10*time.Second, 2*time.Second).Should(HaveOccurred())
	})

	It("installs the DNS redirect before kube-proxy prerouting DNAT", func() {
		checkPod := frameworkutils.BuildBPFCheckPod("kube-system", clientPod.Spec.NodeName)
		checkPod, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, checkPod, s1PodTimeout)
		Expect(err).ToNot(HaveOccurred())
		defer func() {
			_ = fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, checkPod)
		}()

		Eventually(func() []int {
			ruleset, execErr := fw.PodManager.ExecInPod("kube-system", checkPod.Name,
				[]string{"chroot", "/host", "nft", "-nn", "list", "table", "ip", "dns_redirect"})
			if execErr != nil {
				return nil
			}
			return dnsRedirectPreroutingPriorities(ruleset)
		}, time.Minute, 2*time.Second).Should(ContainElement(BeNumerically("<", -100)),
			"DNS redirect chain must run before kube-proxy DNAT priority -100")
	})

	AfterAll(func() {
		if dnsAllowPolicy != nil {
			_ = fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, dnsAllowPolicy)
		}
		if denyAllPolicy != nil {
			_ = fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, denyAllPolicy)
		}
		if baselineDenyAll != nil {
			_ = fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, baselineDenyAll)
		}
		if domainPolicy != nil {
			_ = fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, domainPolicy)
		}
		if adminAllowPolicy != nil {
			_ = fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, adminAllowPolicy)
		}
		if adminDenyPolicy != nil {
			_ = fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, adminDenyPolicy)
		}
		if baselinePolicy != nil {
			_ = fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, baselinePolicy)
		}
		if baselineDeny != nil {
			_ = fw.ClusterNetworkPolicyManager.DeleteClusterNetworkPolicy(ctx, baselineDeny)
		}
		if clientPod != nil {
			_ = fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, clientPod)
		}
		if baselineClient != nil {
			_ = fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, baselineClient)
		}
		if serverService != nil {
			_ = fw.ServiceManager.DeleteService(ctx, serverService)
		}
		if priorityService != nil {
			_ = fw.ServiceManager.DeleteService(ctx, priorityService)
		}
		if baselineService != nil {
			_ = fw.ServiceManager.DeleteService(ctx, baselineService)
		}
		if serverDeployment != nil {
			_ = fw.DeploymentManager.DeleteAndWaitUntilDeploymentDeleted(ctx, serverDeployment)
		}
		_ = fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, s1DNSNamespace)
	})
})

func dnsRedirectPreroutingPriorities(ruleset string) []int {
	chainPattern := regexp.MustCompile(`(?ms)chain\s+prerouting\s*\{(.*?)\n\s*\}`)
	priorityPattern := regexp.MustCompile(`hook\s+prerouting\s+priority\s+(-?\d+)`)
	var priorities []int

	for _, chain := range chainPattern.FindAllStringSubmatch(ruleset, -1) {
		body := chain[1]
		if !strings.Contains(body, "dport 53") || !strings.Contains(body, "dnat") {
			continue
		}
		match := priorityPattern.FindStringSubmatch(body)
		if len(match) != 2 {
			continue
		}
		priority, err := strconv.Atoi(match[1])
		if err == nil {
			priorities = append(priorities, priority)
		}
	}
	return priorities
}

func dnsPolicyFlagEnabled(args []string) bool {
	for i, arg := range args {
		if arg == "--enable-dns-policy=true" {
			return true
		}
		if arg == "--enable-dns-policy" {
			if i+1 < len(args) && (args[i+1] == "true" || args[i+1] == "false") {
				return args[i+1] == "true"
			}
			return true
		}
	}
	return false
}
