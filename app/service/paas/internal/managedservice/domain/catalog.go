// Package domain owns the closed managed-service product rules.
package domain

import (
	"errors"
	"slices"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

const PostgreSQLOfferingID = managedservicev1.PostgreSQLOfferingID
const MySQLOfferingID = managedservicev1.MySQLOfferingID
const ElasticsearchOfferingID = managedservicev1.ElasticsearchOfferingID
const RabbitMQOfferingID = managedservicev1.RabbitMQOfferingID
const LogstashOfferingID = managedservicev1.LogstashOfferingID
const KibanaOfferingID = managedservicev1.KibanaOfferingID
const RedisOfferingID = managedservicev1.RedisOfferingID

// ElasticsearchMatches checks the immutable product dependency selection.
// Account ownership, current use permission and concurrent deletion are
// enforced by the use case and its transactional persistence boundary.
func ElasticsearchMatches(reference managedservicev1.ElasticsearchReference,
	installation managedservicev1.ServiceInstallation, engineVersion, regionID string,
) bool {
	return managedservicev1.ValidateServiceInstallation(installation) == nil &&
		installation.ID == reference.InstallationID && installation.ResourceVersion == reference.ResourceVersion &&
		installation.OfferingID == ElasticsearchOfferingID && installation.Phase == managedservicev1.InstallationReady &&
		installation.EngineVersion == engineVersion && installation.RegionID == regionID
}

type Catalog struct {
	definitions []managedservicev1.ServiceDefinition
	offerings   []managedservicev1.ServiceOffering
}

func DefaultCatalog() Catalog {
	definitions := []managedservicev1.ServiceDefinition{
		newDefinition(managedservicev1.PostgreSQLServiceID, "PostgreSQL", "由 Matrix 管理的关系数据库服务。"),
		newDefinition(managedservicev1.MySQLServiceID, "MySQL", "由 Matrix 管理的关系数据库服务。"),
		newDefinition(managedservicev1.ElasticsearchServiceID, "Elasticsearch", "由 Matrix 管理的搜索与分析服务。"),
		newDefinition(managedservicev1.RabbitMQServiceID, "RabbitMQ", "由 Matrix 管理的消息队列服务。"),
		newDefinition(managedservicev1.LogstashServiceID, "Logstash", "由 Matrix 管理的日志接收与处理服务。"),
		newDefinition(managedservicev1.KibanaServiceID, "Kibana", "连接本账号 Elasticsearch 的可视化分析服务。"),
		newDefinition(managedservicev1.RedisServiceID, "Redis", "由 Matrix 管理、带密码认证与持久化的缓存服务。"),
	}
	references := make(map[string]managedservicev1.ServiceDefinitionReference, len(definitions))
	for _, definition := range definitions {
		references[definition.ID] = referenceOf(definition)
	}
	catalog, err := NewCatalog(definitions, []managedservicev1.ServiceOffering{
		{
			ID: PostgreSQLOfferingID, Service: references[managedservicev1.PostgreSQLServiceID],
			DisplayName:  "PostgreSQL 18",
			Description:  "由 Matrix 在本地区域安装和管理的 PostgreSQL 18 服务。",
			EngineFamily: "postgresql", EngineVersion: "18",
			State: managedservicev1.OfferingAvailable,
			QuotaShapes: []managedservicev1.QuotaShape{
				{ID: "pg-small", DisplayName: "开发型", CPUMillicores: 500, MemoryMiB: 1024, StorageGiB: 10},
				{ID: "pg-medium", DisplayName: "标准型", CPUMillicores: 1000, MemoryMiB: 2048, StorageGiB: 20},
			},
		},
		{
			ID: MySQLOfferingID, Service: references[managedservicev1.MySQLServiceID],
			DisplayName:  "MySQL 8.4 LTS",
			Description:  "由 Matrix 在本地区域安装和管理的 MySQL 8.4 LTS 服务。",
			EngineFamily: "mysql", EngineVersion: "8.4",
			State: managedservicev1.OfferingAvailable,
			QuotaShapes: []managedservicev1.QuotaShape{
				{ID: "mysql-small", DisplayName: "开发型", CPUMillicores: 500, MemoryMiB: 1024, StorageGiB: 10},
				{ID: "mysql-medium", DisplayName: "标准型", CPUMillicores: 1000, MemoryMiB: 2048, StorageGiB: 20},
			},
		},
		{
			ID: ElasticsearchOfferingID, Service: references[managedservicev1.ElasticsearchServiceID],
			DisplayName:  "Elasticsearch 8.19",
			Description:  "由 Matrix 在本地区域安装和管理的 Elasticsearch 8.19 搜索服务。",
			EngineFamily: "elasticsearch", EngineVersion: "8.19.23",
			State: managedservicev1.OfferingAvailable,
			QuotaShapes: []managedservicev1.QuotaShape{
				{ID: "elasticsearch-small", DisplayName: "开发型", CPUMillicores: 1000, MemoryMiB: 1536, StorageGiB: 10},
				{ID: "elasticsearch-medium", DisplayName: "标准型", CPUMillicores: 2000, MemoryMiB: 3072, StorageGiB: 20},
			},
		},
		{
			ID: LogstashOfferingID, Service: references[managedservicev1.LogstashServiceID],
			DisplayName:  "Logstash 8.19",
			Description:  "使用业务账号接收 JSON 日志，并将事件保存在本实例中。",
			EngineFamily: "logstash", EngineVersion: "8.19.23",
			State: managedservicev1.OfferingAvailable,
			QuotaShapes: []managedservicev1.QuotaShape{
				{ID: "logstash-small", DisplayName: "开发型", CPUMillicores: 1000, MemoryMiB: 1536, StorageGiB: 10},
				{ID: "logstash-medium", DisplayName: "标准型", CPUMillicores: 2000, MemoryMiB: 3072, StorageGiB: 20},
			},
		},
		{
			ID: KibanaOfferingID, Service: references[managedservicev1.KibanaServiceID],
			DisplayName: "Kibana 8.19", Description: "选择同区域已就绪的 Elasticsearch，查看数据并保存分析视图。",
			EngineFamily: "kibana", EngineVersion: "8.19.23", State: managedservicev1.OfferingAvailable,
			QuotaShapes: []managedservicev1.QuotaShape{
				{ID: "kibana-small", DisplayName: "开发型", CPUMillicores: 1000, MemoryMiB: 1536, StorageGiB: 10},
				{ID: "kibana-medium", DisplayName: "标准型", CPUMillicores: 2000, MemoryMiB: 3072, StorageGiB: 20},
			},
		},
		{
			ID: RedisOfferingID, Service: references[managedservicev1.RedisServiceID],
			DisplayName: "Redis 8.2", Description: "使用独立业务账号读写数据，以 AOF 保留本实例的数据。",
			EngineFamily: "redis", EngineVersion: "8.2.11", State: managedservicev1.OfferingAvailable,
			QuotaShapes: []managedservicev1.QuotaShape{
				{ID: "redis-small", DisplayName: "开发型", CPUMillicores: 500, MemoryMiB: 512, StorageGiB: 10},
				{ID: "redis-medium", DisplayName: "标准型", CPUMillicores: 1000, MemoryMiB: 1024, StorageGiB: 20},
			},
		},
		{
			ID: RabbitMQOfferingID, Service: references[managedservicev1.RabbitMQServiceID],
			DisplayName:  "RabbitMQ 4.1",
			Description:  "由 Matrix 在本地区域安装和管理的 RabbitMQ 4.1 消息队列服务。",
			EngineFamily: "rabbitmq", EngineVersion: "4.1.8",
			State: managedservicev1.OfferingAvailable,
			QuotaShapes: []managedservicev1.QuotaShape{
				{ID: "rabbitmq-small", DisplayName: "开发型", CPUMillicores: 500, MemoryMiB: 768, StorageGiB: 10},
				{ID: "rabbitmq-medium", DisplayName: "标准型", CPUMillicores: 1000, MemoryMiB: 1536, StorageGiB: 20},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	return catalog
}

func NewCatalog(
	definitions []managedservicev1.ServiceDefinition,
	offerings []managedservicev1.ServiceOffering,
) (Catalog, error) {
	if len(definitions) == 0 || len(definitions) > 32 || len(offerings) == 0 || len(offerings) > 64 {
		return Catalog{}, errors.New("managed-service catalog is invalid")
	}
	definitionCopy := append([]managedservicev1.ServiceDefinition(nil), definitions...)
	definitionByID := make(map[string]managedservicev1.ServiceDefinitionReference, len(definitionCopy))
	for _, definition := range definitionCopy {
		if managedservicev1.ValidateServiceDefinition(definition) != nil {
			return Catalog{}, errors.New("managed-service catalog is invalid")
		}
		if _, duplicate := definitionByID[definition.ID]; duplicate {
			return Catalog{}, errors.New("managed-service catalog is invalid")
		}
		definitionByID[definition.ID] = referenceOf(definition)
	}
	offeringCopy := cloneOfferings(offerings)
	seenOfferings := make(map[string]struct{}, len(offeringCopy))
	referencedDefinitions := make(map[string]struct{}, len(definitionCopy))
	for index := range offeringCopy {
		if managedservicev1.ValidateServiceOffering(offeringCopy[index]) != nil ||
			offeringCopy[index].Service != definitionByID[offeringCopy[index].Service.ID] {
			return Catalog{}, errors.New("managed-service catalog is invalid")
		}
		if _, duplicate := seenOfferings[offeringCopy[index].ID]; duplicate {
			return Catalog{}, errors.New("managed-service catalog is invalid")
		}
		seenOfferings[offeringCopy[index].ID] = struct{}{}
		referencedDefinitions[offeringCopy[index].Service.ID] = struct{}{}
		slices.SortFunc(offeringCopy[index].QuotaShapes, func(left, right managedservicev1.QuotaShape) int {
			if left.ID < right.ID {
				return -1
			}
			if left.ID > right.ID {
				return 1
			}
			return 0
		})
	}
	for _, definition := range definitionCopy {
		if definition.State == managedservicev1.ServiceDefinitionAvailable {
			if _, referenced := referencedDefinitions[definition.ID]; !referenced {
				return Catalog{}, errors.New("managed-service catalog is invalid")
			}
		}
	}
	slices.SortFunc(definitionCopy, func(left, right managedservicev1.ServiceDefinition) int {
		if left.ID < right.ID {
			return -1
		}
		if left.ID > right.ID {
			return 1
		}
		return 0
	})
	slices.SortFunc(offeringCopy, func(left, right managedservicev1.ServiceOffering) int {
		if left.ID < right.ID {
			return -1
		}
		if left.ID > right.ID {
			return 1
		}
		return 0
	})
	return Catalog{definitions: definitionCopy, offerings: offeringCopy}, nil
}

func (catalog Catalog) ListServices() []managedservicev1.ServiceDefinition {
	return append([]managedservicev1.ServiceDefinition(nil), catalog.definitions...)
}

func (catalog Catalog) ResolveService(id string) (managedservicev1.ServiceDefinition, bool) {
	for _, definition := range catalog.definitions {
		if definition.ID == id {
			return definition, true
		}
	}
	return managedservicev1.ServiceDefinition{}, false
}

func (catalog Catalog) List() []managedservicev1.ServiceOffering {
	return cloneOfferings(catalog.offerings)
}

func (catalog Catalog) Resolve(
	offeringID string,
	quotaShapeID string,
) (managedservicev1.ServiceOffering, managedservicev1.QuotaShape, bool) {
	for _, offering := range catalog.offerings {
		if offering.ID != offeringID || offering.State != managedservicev1.OfferingAvailable {
			continue
		}
		for _, shape := range offering.QuotaShapes {
			if shape.ID == quotaShapeID {
				copy := cloneOfferings([]managedservicev1.ServiceOffering{offering})[0]
				return copy, shape, true
			}
		}
	}
	return managedservicev1.ServiceOffering{}, managedservicev1.QuotaShape{}, false
}

func cloneOfferings(values []managedservicev1.ServiceOffering) []managedservicev1.ServiceOffering {
	result := slices.Clone(values)
	for index := range result {
		result[index].QuotaShapes = slices.Clone(result[index].QuotaShapes)
	}
	return result
}

func newDefinition(id, displayName, description string) managedservicev1.ServiceDefinition {
	result := managedservicev1.ServiceDefinition{
		ID: id, DisplayName: displayName, Description: description, Revision: 1,
		ActivationPrerequisite: managedservicev1.ServiceActivationPermissionOnly,
		State:                  managedservicev1.ServiceDefinitionAvailable,
	}
	_, digest, err := managedservicev1.CanonicalizeServiceDefinition(result)
	if err != nil {
		panic(err)
	}
	result.ContentDigest = digest
	return result
}

func referenceOf(value managedservicev1.ServiceDefinition) managedservicev1.ServiceDefinitionReference {
	return managedservicev1.ServiceDefinitionReference{
		ID: value.ID, Revision: value.Revision, ContentDigest: value.ContentDigest,
	}
}
