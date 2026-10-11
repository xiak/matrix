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

type Catalog struct {
	offerings []managedservicev1.ServiceOffering
}

func DefaultCatalog() Catalog {
	catalog, err := NewCatalog([]managedservicev1.ServiceOffering{
		{
			ID: PostgreSQLOfferingID, Kind: managedservicev1.OfferingPostgreSQL,
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
			ID: MySQLOfferingID, Kind: managedservicev1.OfferingMySQL,
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
			ID: ElasticsearchOfferingID, Kind: managedservicev1.OfferingElasticsearch,
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
			ID: RabbitMQOfferingID, Kind: managedservicev1.OfferingRabbitMQ,
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

func NewCatalog(offerings []managedservicev1.ServiceOffering) (Catalog, error) {
	if len(offerings) == 0 || len(offerings) > 32 {
		return Catalog{}, errors.New("managed-service catalog is invalid")
	}
	copy := cloneOfferings(offerings)
	seen := make(map[string]struct{}, len(copy))
	for index := range copy {
		if managedservicev1.ValidateServiceOffering(copy[index]) != nil {
			return Catalog{}, errors.New("managed-service catalog is invalid")
		}
		if _, duplicate := seen[copy[index].ID]; duplicate {
			return Catalog{}, errors.New("managed-service catalog is invalid")
		}
		seen[copy[index].ID] = struct{}{}
		slices.SortFunc(copy[index].QuotaShapes, func(left, right managedservicev1.QuotaShape) int {
			if left.ID < right.ID {
				return -1
			}
			if left.ID > right.ID {
				return 1
			}
			return 0
		})
	}
	slices.SortFunc(copy, func(left, right managedservicev1.ServiceOffering) int {
		if left.ID < right.ID {
			return -1
		}
		if left.ID > right.ID {
			return 1
		}
		return 0
	})
	return Catalog{offerings: copy}, nil
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
