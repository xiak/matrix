package releasebuild

const (
	APISIXBaseReference   = "apache/apisix:3.17.0-debian"
	APISIXBaseImageID     = "sha256:6cbf65f3085d1386bfd636b7e88400c163c3641841909e674af7896a5766b092"
	DockerBaseReference   = "docker:27.5.1-dind-alpine3.21"
	DockerBaseImageID     = "sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce"
	PostgresReference     = "postgres:18"
	PostgresImageID       = "sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a"
	minimumDockerVersion  = "27.5.1"
	minimumComposeVersion = "2.33.0"
)

type binarySpecification struct {
	name        string
	packagePath string
}

var binarySpecifications = []binarySpecification{
	{name: "matrix-audit", packagePath: "./app/service/audit/cmd/matrix-audit"},
	{name: "matrix-audit-migrate", packagePath: "./app/service/audit/cmd/matrix-audit-migrate"},
	{name: "matrix-health", packagePath: "./app/service/installation/cmd/matrix-health"},
	{name: "matrix-iam", packagePath: "./app/service/iam/cmd/matrix-iam"},
	{name: "matrix-iam-audit-dispatcher", packagePath: "./app/service/iam/cmd/matrix-iam-audit-dispatcher"},
	{name: "matrix-iam-migrate", packagePath: "./app/service/iam/cmd/matrix-iam-migrate"},
	{name: "matrix-paas", packagePath: "./app/service/paas/cmd/matrix-paas"},
	{name: "matrix-paas-audit-dispatcher", packagePath: "./app/service/paas/cmd/matrix-paas-audit-dispatcher"},
	{name: "matrix-paas-migrate", packagePath: "./app/service/paas/cmd/matrix-paas-migrate"},
	{name: "matrix-paas-ui", packagePath: "./app/ui/paas/cmd/matrix-paas-ui"},
	{name: "matrix-paas-worker", packagePath: "./app/service/paas/cmd/matrix-paas-worker"},
	{name: "matrix-verification", packagePath: "./app/service/installation/cmd/matrix-verification"},
	{name: "mx", packagePath: "./app/service/installation/cmd/mx"},
}

type imageRecipe struct {
	component     string
	baseReference string
	binaries      []string
	entrypoint    string
}

var imageRecipes = []imageRecipe{
	{
		component: "apisix", baseReference: APISIXBaseReference,
		binaries: []string{"matrix-health"},
	},
	{
		component: "audit", baseReference: "scratch",
		binaries: []string{"matrix-audit", "matrix-audit-migrate", "matrix-health"},
	},
	{
		component: "iam", baseReference: "scratch",
		binaries: []string{"matrix-iam", "matrix-iam-audit-dispatcher", "matrix-iam-migrate", "matrix-health"},
	},
	{
		component: "paas", baseReference: DockerBaseReference,
		binaries: []string{
			"matrix-paas", "matrix-paas-audit-dispatcher", "matrix-paas-migrate",
			"matrix-paas-worker", "matrix-health",
		},
	},
	{
		component: "paas-ui", baseReference: "scratch",
		binaries:   []string{"matrix-paas-ui", "matrix-health"},
		entrypoint: "/matrix/bin/matrix-paas-ui",
	},
	{
		component: "verification", baseReference: "scratch",
		binaries:   []string{"matrix-verification"},
		entrypoint: "/matrix/bin/matrix-verification",
	},
}
