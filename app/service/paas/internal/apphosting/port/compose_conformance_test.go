package port_test

import (
	"github.com/xiak/matrix/app/adapter/apphosting/compose"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

var _ port.DeploymentExecutor = (*compose.Executor)(nil)
