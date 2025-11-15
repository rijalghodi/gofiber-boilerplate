package contract

type HealthCheck struct {
	IsUp    bool    `json:"isUp"`
	Name    string  `json:"name"`
	Status  string  `json:"status"`
	Message *string `json:"message"`
}

type HealthCheckResponse struct {
	Code      int           `json:"code"`
	Status    string        `json:"status"`
	Message   string        `json:"message"`
	IsHealthy bool          `json:"isHealthy"`
	Result    []HealthCheck `json:"result"`
}
