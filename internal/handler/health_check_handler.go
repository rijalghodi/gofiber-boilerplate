package handler

import (
	"app/internal/contract"
	"app/internal/usecase"

	"github.com/gofiber/fiber/v2"
)

type HealthCheckController struct {
	HealthCheckUsecase usecase.HealthCheckUsecase
}

func NewHealthCheckController(healthCheckUsecase usecase.HealthCheckUsecase) *HealthCheckController {
	return &HealthCheckController{
		HealthCheckUsecase: healthCheckUsecase,
	}
}

func (h *HealthCheckController) RegisterRoutes(app *fiber.App) {
	app.Get("/health-check", h.Check)
}

func (h *HealthCheckController) addServiceStatus(
	serviceList *[]contract.HealthCheck, name string, isUp bool, message *string,
) {
	status := "Up"

	if !isUp {
		status = "Down"
	}

	*serviceList = append(*serviceList, contract.HealthCheck{
		Name:    name,
		Status:  status,
		IsUp:    isUp,
		Message: message,
	})
}

// @Tags Health
// @Summary Health Check
// @Description Check the status of services and database connections
// @Accept json
// @Produce json
// @Success 200 {object} example.HealthCheckResponse
// @Failure 500 {object} example.HealthCheckResponseError
// @Router /health-check [get]
func (h *HealthCheckController) Check(c *fiber.Ctx) error {
	isHealthy := true
	var serviceList []contract.HealthCheck

	// Check the database connection
	if err := h.HealthCheckUsecase.GormCheck(); err != nil {
		isHealthy = false
		errMsg := err.Error()
		h.addServiceStatus(&serviceList, "Postgre", false, &errMsg)
	} else {
		h.addServiceStatus(&serviceList, "Postgre", true, nil)
	}

	if err := h.HealthCheckUsecase.MemoryHeapCheck(); err != nil {
		isHealthy = false
		errMsg := err.Error()
		h.addServiceStatus(&serviceList, "Memory", false, &errMsg)
	} else {
		h.addServiceStatus(&serviceList, "Memory", true, nil)
	}

	// Return the response based on health check result
	statusCode := fiber.StatusOK
	status := "success"

	if !isHealthy {
		statusCode = fiber.StatusInternalServerError
		status = "error"
	}

	return c.Status(statusCode).JSON(contract.HealthCheckResponse{
		Status:    status,
		Message:   "Health check completed",
		Code:      statusCode,
		IsHealthy: isHealthy,
		Result:    serviceList,
	})
}
