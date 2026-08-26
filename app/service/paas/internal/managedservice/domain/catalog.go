// Package domain owns the closed managed-service product rules.
package domain

import (
	"errors"
	"slices"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

const PostgreSQLOfferingID = managedservicev1.PostgreSQLOfferingID

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
	})
	if err != nil {
		panic(err)
	}
	return catalog
}

func NewCatalog(offerings []managedservicev1.ServiceOffering) (Catalog, error) {
	if len(offerings) != 1 || offerings[0].ID != PostgreSQLOfferingID ||
		offerings[0].Kind != managedservicev1.OfferingPostgreSQL ||
		offerings[0].State != managedservicev1.OfferingAvailable ||
		managedservicev1.ValidateServiceOffering(offerings[0]) != nil {
		return Catalog{}, errors.New("managed-service catalog is invalid")
	}
	copy := cloneOfferings(offerings)
	slices.SortFunc(copy[0].QuotaShapes, func(left, right managedservicev1.QuotaShape) int {
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
