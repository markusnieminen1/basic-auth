package setup

var (
	// --------------
	// Headers
	// --------------

	ACCESS_TOKEN_NAME         = "Authorization"   // Headers
	REFRESH_TOKEN_NAME        = "X-Refresh-Token" // Headers
	ACCESS_TOKEN_EXPIRY_MIN   = 5
	REFRESH_TOKEN_EXPIRY_DAYS = 14

	// --------------
	// Password
	// --------------

	PWD_MinLength    = 10 // Password
	PWD_MinUppercase = 1  // Password
	PWD_MinLowercase = 1  // Password
	PWD_MinDigits    = 1  // Password
	PWD_MinSymbols   = 1  // Password

	PWD_ForbiddenChars = " " // Password, every character in the string is rejected, e.g. " \t" or "<>"

	// --------------
	// Username
	// --------------

	UName_MinLength         = 3    // Username
	UName_MaxLength         = 30   // Username
	UName_AllowSpecialChars = true // Username

	UName_ForbiddenChars = "" // Username, every character in the string is rejected on top of the allowed character rules

	// --------------
	// Middleware
	// --------------

	RequestPerInterval                 = 8    // General ratelimiter
	RequesIntervalMillis               = 1000 // General ratelimiter
	ProtectedRouteRequestPerInterval   = 5    // ratelimiter for protected endpoints, makes it possible to have lower threshold for endpoinds that requires processing
	ProtectedRouteRequesIntervalMillis = 1000 // ratelimiter for protected endpoints, makes it possible to have lower threshold for endpoinds that requires processing

	// --------------
	// Database
	// --------------

	AuthDbDefaultPath = "./auth.db"
)
