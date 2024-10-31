package traefik_telegram_initdata_introspector

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Config struct {
	ProxyHeaderName string `json:"proxyHeaderName,omitempty"`
	AuthHeader      string `json:"authHeader,omitempty"`
	Optional        bool   `json:"optional,omitempty"`
	BotToken        string `json:"clientSecret,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type RequestData struct {
	next            http.Handler
	name            string
	proxyHeaderName string
	authHeader      string
	optional        bool
	BotToken        string
}

// Struct to hold the parsed and decoded Telegram data
type TelegramUser struct {
	ID              int64  `json:"id"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	Username        string `json:"username"`
	LanguageCode    string `json:"language_code"`
	AllowsWriteToPM bool   `json:"allows_write_to_pm"`
}

type TelegramInitData struct {
	User         TelegramUser `json:"user"`
	ChatInstance string       `json:"chat_instance"`
	ChatType     string       `json:"chat_type"`
	AuthDate     string       `json:"auth_date"`
	Hash         string       `json:"hash"`
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.ProxyHeaderName) == 0 {
		config.ProxyHeaderName = "injectedPayload"
	}
	if len(config.AuthHeader) == 0 {
		config.AuthHeader = "Authorization"
	}
	if len(config.BotToken) == 0 {
		return nil, fmt.Errorf("BotToken cannot be empty")
	}

	return &RequestData{
		next:            next,
		name:            name,
		proxyHeaderName: config.ProxyHeaderName, // injectedPayload
		authHeader:      config.AuthHeader,      // Incoming request header name
		optional:        config.Optional,        // Should pass request if it is empty?
		BotToken:        config.BotToken,        // Telegram Bot Token
	}, nil
}

func (j *RequestData) ServeHTTP(res http.ResponseWriter, req *http.Request) {

	telegramInitString := strings.Trim(req.Header.Get(j.authHeader), " ")

	// Delete the header we inject if they already are in the request
	// to avoid people trying to inject stuff
	req.Header.Del(j.proxyHeaderName)

	if j.optional == true && len(telegramInitString) == 0 {
		j.next.ServeHTTP(res, req)
		return
	} else if j.optional == false && len(telegramInitString) == 0 {
		errorMessageTxt := "access denied"
		http.Error(res, errorMessageTxt, http.StatusUnauthorized)
		return
	}

	isValid, decodedData, err := ValidateTelegramInitData(telegramInitString, j.BotToken)

	if err != nil {
		res.Header().Set("Content-Type", "application/json")
		errorMessageTxt := "internal error"
		http.Error(res, errorMessageTxt, http.StatusInternalServerError)
		return
	}

	if isValid {

		// Convert decodedData to JSON
		decodedDataJSON, err := json.Marshal(decodedData)
		if err != nil {
			log.Fatalf("Error converting to JSON: %v\n", err)
			return
		}

		req.Header.Set(j.proxyHeaderName, string(decodedDataJSON))
		j.next.ServeHTTP(res, req)
		return
	} else {
		errorMessageTxt := "invalid token"
		http.Error(res, errorMessageTxt, http.StatusUnauthorized)
		return
	}

}

// Function to validate and decode Telegram initData
func ValidateTelegramInitData(initData, botTokenSecret string) (bool, TelegramInitData, error) {
	// Parse initData query parameters
	values, err := url.ParseQuery(initData)
	if err != nil {
		return false, TelegramInitData{}, fmt.Errorf("failed to parse initData: %v", err)
	}

	// Extract the user field and decode JSON string to TelegramUser struct
	userStr := values.Get("user")
	var user TelegramUser
	if err := json.Unmarshal([]byte(userStr), &user); err != nil {
		return false, TelegramInitData{}, fmt.Errorf("failed to decode user JSON: %v", err)
	}

	// Populate the TelegramInitData struct
	data := TelegramInitData{
		User:         user,
		ChatInstance: values.Get("chat_instance"),
		ChatType:     values.Get("chat_type"),
		AuthDate:     values.Get("auth_date"),
		Hash:         values.Get("hash"),
	}

	// Check for hash presence
	if data.Hash == "" {
		return false, data, fmt.Errorf("missing hash in initData")
	}

	// Prepare data_check_string for HMAC verification
	dataCheckString := buildDataCheckString(values)
	secretKey := generateSecretKey(botTokenSecret)

	// Validate hash
	expectedHash := calculateHMACSHA256(dataCheckString, secretKey)
	return expectedHash == data.Hash, data, nil
}

// Helper to generate secret key from bot token
func generateSecretKey(botTokenSecret string) []byte {
	h := sha256.New()
	h.Write([]byte(botTokenSecret))
	h.Write([]byte("WebAppData"))
	return h.Sum(nil)
}

// Helper to calculate HMAC-SHA256
func calculateHMACSHA256(data string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Helper to build data_check_string
func buildDataCheckString(values url.Values) string {
	var components []string
	for key, val := range values {
		if key != "hash" {
			components = append(components, key+"="+val[0])
		}
	}
	return strings.Join(components, "\n")
}
