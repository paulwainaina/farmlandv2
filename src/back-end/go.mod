module example.com/farmland

go 1.21.0

require (
	example.com/sessions v0.0.0-00010101000000-000000000000
	github.com/joho/godotenv v1.5.1
)

require github.com/google/uuid v1.3.1 // indirect

replace example.com/sessions => ../modules/sessions
