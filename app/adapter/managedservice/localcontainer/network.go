package localcontainer

import "fmt"

// PrivateNetworks gives a product no host route or directly published port.
// A bounded, unprivileged endpoint is the only bridge to the host-facing network.
func PrivateNetworks() map[string]any {
	return map[string]any{
		"private": map[string]any{
			"internal": true, "driver": "bridge", "enable_ipv6": false,
			"driver_opts": map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
		},
		// Keep Compose's implicit bridge configuration. Explicitly adding the
		// same driver changes its network hash; Compose would try to remove
		// the still-attached predecessor network before recreating MySQL.
		"default": map[string]any{},
	}
}

// EndpointService is composed only by product code. Service and targetPort are
// fixed product facts, never caller-supplied endpoint or native configuration.
func EndpointService(imageID string, port int, service string, targetPort int, labels map[string]string) map[string]any {
	return map[string]any{
		"image": imageID, "pull_policy": "never", "restart": "unless-stopped",
		"entrypoint": []string{"/matrix/bin/matrix-product-endpoint"}, "command": []string{fmt.Sprintf("%s:%d", service, targetPort)},
		"user": "65532:65532", "read_only": true, "pids_limit": 32,
		// The signed PaaS image inherits a Docker data VOLUME. Override it
		// with bounded tmpfs so this socket-free process creates no volume.
		"tmpfs":    []string{"/var/lib/docker:rw,noexec,nosuid,nodev,size=1m"},
		"networks": []string{"private", "default"},
		"ports":    []string{fmt.Sprintf("127.0.0.1:%d:13306/tcp", port)},
		"cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges:true"},
		"sysctls":     map[string]string{"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"},
		"environment": map[string]string{"GOMAXPROCS": "1", "GOMEMLIMIT": "48MiB"},
		"depends_on":  map[string]any{service: map[string]string{"condition": "service_healthy"}},
		"healthcheck": map[string]any{
			"test":     []string{"CMD", "/matrix/bin/matrix-product-endpoint", "--check"},
			"interval": "5s", "timeout": "4s", "retries": 6,
		},
		"deploy": map[string]any{"resources": map[string]any{"limits": map[string]any{"cpus": "0.25", "memory": "64M", "pids": 32}}},
		"labels": labels,
	}
}
