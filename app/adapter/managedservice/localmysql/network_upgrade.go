package localmysql

import (
	"context"
	"errors"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	localcontainer "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

// UpgradeNetwork preserves the installed MySQL data and credentials while moving
// direct-port predecessors behind the same private ingress used by new instances.
func (provisioner *Provisioner) UpgradeNetwork(ctx context.Context) error {
	if provisioner == nil {
		return errors.New("local MySQL provisioner is unavailable")
	}
	return localcontainer.UpgradeNetwork(ctx, localcontainer.NetworkUpgrade{
		Root: provisioner.root, Runtime: provisioner.runtime,
		ServiceName: mysqlServiceName, EndpointServiceName: endpointServiceName,
		OfferingID: managedservicev1.MySQLOfferingID, TargetPort: 3306,
		Mounts: map[string]string{"/var/lib/mysql": "data", "/run/secrets/mysql-password": "mysql-password", "/run/secrets/mysql-root-password": "mysql-root-password"},
		Endpoint: func(port int, labels map[string]string) map[string]any {
			return endpointService(provisioner.endpointImageID, port, labels)
		},
	})
}
