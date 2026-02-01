package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

type NmapRequest struct {
	Targets string `json:"targets" binding:"required"` // IP addresses or ranges (e.g., "192.168.1.1" or "192.168.1.0/24")
	Ports   string `json:"ports"`                      // Port range (e.g., "22,80,443" or "1-1000")
	Options string `json:"options"`                    // Additional nmap options (e.g., "-sV -sC")
}

type NiktoRequest struct {
	Target  string `json:"target" binding:"required"` // Target URL or IP
	Port    string `json:"port"`                      // Port (default: 80)
	Options string `json:"options"`                   // Additional nikto options
}

type DirbRequest struct {
	Target   string `json:"target" binding:"required"` // Target URL
	Wordlist string `json:"wordlist"`                  // Path to wordlist (default: /usr/share/wordlists/dirb/common.txt)
	Options  string `json:"options"`                   // Additional dirb options
}

type WhatWebRequest struct {
	Target  string `json:"target" binding:"required"` // Target URL or IP
	Options string `json:"options"`                   // Additional whatweb options (e.g., "-a 3" for aggression level)
}

type DigRequest struct {
	Domain  string `json:"domain" binding:"required"` // Domain name to lookup
	Type    string `json:"type"`                      // Record type (A, MX, NS, TXT, etc.)
	Server  string `json:"server"`                    // DNS server to query
	Options string `json:"options"`                   // Additional dig options
}

type WhoisRequest struct {
	Domain  string `json:"domain" binding:"required"` // Domain or IP to lookup
	Options string `json:"options"`                   // Additional whois options
}

type HarvesterRequest struct {
	Domain  string `json:"domain" binding:"required"` // Domain to search
	Source  string `json:"source"`                    // Data source (e.g., "google", "bing", "all")
	Limit   string `json:"limit"`                     // Limit results
	Options string `json:"options"`                   // Additional theHarvester options
}

type MasscanRequest struct {
	Targets string `json:"targets" binding:"required"` // IP addresses or ranges
	Ports   string `json:"ports" binding:"required"`   // Port range (e.g., "1-1000")
	Rate    string `json:"rate"`                       // Packet rate (e.g., "1000")
	Options string `json:"options"`                    // Additional masscan options
}

type CommandResponse struct {
	Success bool   `json:"success"`
	Output  string `json:"output"`
	Error   string `json:"error,omitempty"`
}

// Global configuration
var config struct {
	allowedNetworks []*net.IPNet
	restrictTargets bool
}

func main() {
	// Command-line flags with environment variable defaults
	defaultAllowedNets := os.Getenv("ALLOWED_NETWORKS")
	if defaultAllowedNets == "" {
		defaultAllowedNets = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
	}

	addr := flag.String("addr", ":8080", "Listen address (e.g., :8080, 0.0.0.0:8080)")
	allowedNets := flag.String("allowed-networks", defaultAllowedNets, "Comma-separated list of allowed CIDR networks (default: RFC1918 private networks)")
	restrictTargets := flag.Bool("restrict-targets", true, "Restrict scan targets to allowed networks only")
	flag.Parse()

	// Environment variable override
	if envAddr := os.Getenv("LISTEN_ADDR"); envAddr != "" {
		*addr = envAddr
	}

	// Parse allowed networks
	config.restrictTargets = *restrictTargets
	if config.restrictTargets {
		for _, cidr := range strings.Split(*allowedNets, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Fatalf("Invalid CIDR network '%s': %v", cidr, err)
			}
			config.allowedNetworks = append(config.allowedNetworks, ipnet)
		}
		log.Printf("Target restriction enabled. Allowed networks: %s", *allowedNets)
	} else {
		log.Printf("WARNING: Target restriction disabled. Tools can scan ANY network!")
	}

	r := gin.Default()

	r.GET("/health", healthHandler)
	r.POST("/nmap", nmapHandler)
	r.POST("/nikto", niktoHandler)
	r.POST("/dirb", dirbHandler)
	r.POST("/whatweb", whatwebHandler)
	r.POST("/dig", digHandler)
	r.POST("/whois", whoisHandler)
	r.POST("/harvester", harvesterHandler)
	r.POST("/masscan", masscanHandler)

	log.Printf("Kali Command Server starting on %s", *addr)
	if err := r.Run(*addr); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// validateTarget checks if a target (IP, hostname, or URL) is allowed
func validateTarget(target string) error {
	if !config.restrictTargets {
		return nil
	}

	// Extract hostname/IP from URL if needed
	targetHost := target
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return fmt.Errorf("invalid URL format: %v", err)
		}
		targetHost = u.Hostname()
	}

	// Remove port if present
	if host, _, err := net.SplitHostPort(targetHost); err == nil {
		targetHost = host
	}

	// Try to parse as IP first
	ip := net.ParseIP(targetHost)
	if ip != nil {
		return validateIP(ip)
	}

	// If it's a hostname, resolve it
	ips, err := net.LookupIP(targetHost)
	if err != nil {
		return fmt.Errorf("cannot resolve hostname '%s': %v", targetHost, err)
	}

	// Check all resolved IPs
	for _, ip := range ips {
		if err := validateIP(ip); err != nil {
			return fmt.Errorf("hostname '%s' resolves to disallowed IP %s", targetHost, ip)
		}
	}

	return nil
}

// validateIP checks if an IP is in the allowed networks
func validateIP(ip net.IP) error {
	if !config.restrictTargets {
		return nil
	}

	for _, ipnet := range config.allowedNetworks {
		if ipnet.Contains(ip) {
			return nil
		}
	}

	return fmt.Errorf("IP %s is not in allowed networks", ip)
}

// validateTargets validates multiple targets (comma or space separated IPs/ranges)
func validateTargets(targets string) error {
	if !config.restrictTargets {
		return nil
	}

	// Split by common delimiters
	targetList := regexp.MustCompile(`[,\s]+`).Split(targets, -1)

	for _, target := range targetList {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// Check for CIDR notation
		if strings.Contains(target, "/") {
			_, ipnet, err := net.ParseCIDR(target)
			if err != nil {
				return fmt.Errorf("invalid CIDR '%s': %v", target, err)
			}
			// Check if the network is within allowed ranges
			if err := validateIP(ipnet.IP); err != nil {
				return fmt.Errorf("CIDR network %s not allowed: %v", target, err)
			}
		} else if strings.Contains(target, "-") {
			// IP range notation (e.g., 192.168.1.1-50)
			// Just validate the base IP
			parts := strings.Split(target, "-")
			if err := validateTarget(parts[0]); err != nil {
				return fmt.Errorf("IP range %s not allowed: %v", target, err)
			}
		} else {
			// Single IP or hostname
			if err := validateTarget(target); err != nil {
				return err
			}
		}
	}

	return nil
}

func nmapHandler(c *gin.Context) {
	var req NmapRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CommandResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	// Validate targets
	if err := validateTargets(req.Targets); err != nil {
		c.JSON(http.StatusForbidden, CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Target validation failed: %v", err),
		})
		return
	}

	// Build nmap command arguments
	args := []string{}

	if req.Ports != "" {
		args = append(args, "-p", req.Ports)
	}

	if req.Options != "" {
		args = append(args, strings.Fields(req.Options)...)
	}

	args = append(args, req.Targets)

	log.Printf("Executing: nmap %s", strings.Join(args, " "))

	cmd := exec.Command("nmap", args...)
	output, err := cmd.CombinedOutput()

	response := CommandResponse{
		Success: err == nil,
		Output:  string(output),
	}

	if err != nil {
		response.Error = fmt.Sprintf("Command failed: %v", err)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	c.JSON(http.StatusOK, response)
}

func niktoHandler(c *gin.Context) {
	var req NiktoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CommandResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	// Validate target
	if err := validateTarget(req.Target); err != nil {
		c.JSON(http.StatusForbidden, CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Target validation failed: %v", err),
		})
		return
	}

	args := []string{"-h", req.Target}

	if req.Port != "" {
		args = append(args, "-p", req.Port)
	}

	if req.Options != "" {
		args = append(args, strings.Fields(req.Options)...)
	}

	log.Printf("Executing: nikto %s", strings.Join(args, " "))

	cmd := exec.Command("nikto", args...)
	output, err := cmd.CombinedOutput()

	response := CommandResponse{
		Success: err == nil,
		Output:  string(output),
	}

	if err != nil {
		response.Error = fmt.Sprintf("Command failed: %v", err)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	c.JSON(http.StatusOK, response)
}

func dirbHandler(c *gin.Context) {
	var req DirbRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CommandResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	// Validate target
	if err := validateTarget(req.Target); err != nil {
		c.JSON(http.StatusForbidden, CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Target validation failed: %v", err),
		})
		return
	}

	args := []string{req.Target}

	wordlist := req.Wordlist
	if wordlist == "" {
		wordlist = "/usr/share/wordlists/dirb/common.txt"
	}
	args = append(args, wordlist)

	if req.Options != "" {
		args = append(args, strings.Fields(req.Options)...)
	}

	log.Printf("Executing: dirb %s", strings.Join(args, " "))

	cmd := exec.Command("dirb", args...)
	output, err := cmd.CombinedOutput()

	response := CommandResponse{
		Success: err == nil,
		Output:  string(output),
	}

	if err != nil {
		response.Error = fmt.Sprintf("Command failed: %v", err)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	c.JSON(http.StatusOK, response)
}

func whatwebHandler(c *gin.Context) {
	var req WhatWebRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CommandResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	// Validate target
	if err := validateTarget(req.Target); err != nil {
		c.JSON(http.StatusForbidden, CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Target validation failed: %v", err),
		})
		return
	}

	args := []string{req.Target}

	if req.Options != "" {
		args = append(args, strings.Fields(req.Options)...)
	}

	log.Printf("Executing: whatweb %s", strings.Join(args, " "))

	cmd := exec.Command("whatweb", args...)
	output, err := cmd.CombinedOutput()

	response := CommandResponse{
		Success: err == nil,
		Output:  string(output),
	}

	if err != nil {
		response.Error = fmt.Sprintf("Command failed: %v", err)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	c.JSON(http.StatusOK, response)
}

func digHandler(c *gin.Context) {
	var req DigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CommandResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	args := []string{}

	if req.Type != "" {
		args = append(args, req.Type)
	}

	args = append(args, req.Domain)

	if req.Server != "" {
		args = append(args, "@"+req.Server)
	}

	if req.Options != "" {
		args = append(args, strings.Fields(req.Options)...)
	}

	log.Printf("Executing: dig %s", strings.Join(args, " "))

	cmd := exec.Command("dig", args...)
	output, err := cmd.CombinedOutput()

	response := CommandResponse{
		Success: err == nil,
		Output:  string(output),
	}

	if err != nil {
		response.Error = fmt.Sprintf("Command failed: %v", err)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	c.JSON(http.StatusOK, response)
}

func whoisHandler(c *gin.Context) {
	var req WhoisRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CommandResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	args := []string{req.Domain}

	if req.Options != "" {
		args = append(args, strings.Fields(req.Options)...)
	}

	log.Printf("Executing: whois %s", strings.Join(args, " "))

	cmd := exec.Command("whois", args...)
	output, err := cmd.CombinedOutput()

	response := CommandResponse{
		Success: err == nil,
		Output:  string(output),
	}

	if err != nil {
		response.Error = fmt.Sprintf("Command failed: %v", err)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	c.JSON(http.StatusOK, response)
}

func harvesterHandler(c *gin.Context) {
	var req HarvesterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CommandResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	args := []string{"-d", req.Domain}

	if req.Source != "" {
		args = append(args, "-b", req.Source)
	}

	if req.Limit != "" {
		args = append(args, "-l", req.Limit)
	}

	if req.Options != "" {
		args = append(args, strings.Fields(req.Options)...)
	}

	log.Printf("Executing: theHarvester %s", strings.Join(args, " "))

	cmd := exec.Command("theHarvester", args...)
	output, err := cmd.CombinedOutput()

	response := CommandResponse{
		Success: err == nil,
		Output:  string(output),
	}

	if err != nil {
		response.Error = fmt.Sprintf("Command failed: %v", err)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	c.JSON(http.StatusOK, response)
}

func masscanHandler(c *gin.Context) {
	var req MasscanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CommandResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	// Validate targets
	if err := validateTargets(req.Targets); err != nil {
		c.JSON(http.StatusForbidden, CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Target validation failed: %v", err),
		})
		return
	}

	args := []string{req.Targets, "-p", req.Ports}

	if req.Rate != "" {
		args = append(args, "--rate", req.Rate)
	}

	if req.Options != "" {
		args = append(args, strings.Fields(req.Options)...)
	}

	log.Printf("Executing: masscan %s", strings.Join(args, " "))

	cmd := exec.Command("masscan", args...)
	output, err := cmd.CombinedOutput()

	response := CommandResponse{
		Success: err == nil,
		Output:  string(output),
	}

	if err != nil {
		response.Error = fmt.Sprintf("Command failed: %v", err)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	c.JSON(http.StatusOK, response)
}
