package usecase

import (
	"app/pkg/logger"
	"errors"
	"runtime"

	"gorm.io/gorm"
)

type HealthCheckUsecase interface {
	GormCheck() error
	MemoryHeapCheck() error
}

type healthCheckUsecase struct {
	DB *gorm.DB
}

func NewHealthCheckUsecase(db *gorm.DB) HealthCheckUsecase {
	return &healthCheckUsecase{
		DB: db,
	}
}

func (s *healthCheckUsecase) GormCheck() error {
	sqlDB, errDB := s.DB.DB()
	if errDB != nil {
		logger.Log.Errorf("failed to access the database connection pool: %v", errDB)
		return errDB
	}

	if err := sqlDB.Ping(); err != nil {
		logger.Log.Errorf("failed to ping the database: %v", err)
		return err
	}

	return nil
}

// MemoryHeapCheck checks if heap memory usage exceeds a threshold
func (s *healthCheckUsecase) MemoryHeapCheck() error {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats) // Collect memory statistics

	heapAlloc := memStats.HeapAlloc            // Heap memory currently allocated
	heapThreshold := uint64(300 * 1024 * 1024) // Example threshold: 300 MB

	logger.Log.Infof("Heap Memory Allocation: %v bytes", heapAlloc)

	// If the heap allocation exceeds the threshold, return an error
	if heapAlloc > heapThreshold {
		logger.Log.Errorf("Heap memory usage exceeds threshold: %v bytes", heapAlloc)
		return errors.New("heap memory usage too high")
	}

	return nil
}
