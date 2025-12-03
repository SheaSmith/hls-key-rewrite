package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/playlist.m3u8", proxyHandler)

	log.Printf("Starting HLS Proxy on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	hexKey := r.URL.Query().Get("key")

	if targetURL == "" || hexKey == "" {
		http.Error(w, "Missing 'url' or 'key' query parameters", http.StatusBadRequest)
		return
	}

	// Validate hex key
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		http.Error(w, "Invalid hex key", http.StatusBadRequest)
		return
	}
	base64Key := base64.StdEncoding.EncodeToString(keyBytes)

	// Fetch upstream
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch upstream: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Upstream returned status: %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	// Resolve base URL for relative paths
	u, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid upstream URL", http.StatusInternalServerError)
		return
	}
	baseURL := u.Scheme + "://" + u.Host + u.Path
	// Strip last component to get directory
	if idx := strings.LastIndex(baseURL, "/"); idx != -1 {
		baseURL = baseURL[:idx+1]
	}

	// Set headers
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("Access-Control-Allow-Origin", "*")

	scanner := bufio.NewScanner(resp.Body)
	isMaster := false
	
	// Buffer output to determine type and process
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
		if strings.HasPrefix(line, "#EXT-X-STREAM-INF") {
			isMaster = true
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading upstream body: %v", err)
		return
	}

	if isMaster {
		processMasterPlaylist(w, lines, hexKey, baseURL)
	} else {
		processMediaPlaylist(w, lines, base64Key, baseURL)
	}
}

func processMasterPlaylist(w http.ResponseWriter, lines []string, hexKey, baseURL string) {
	var bestVariant string
	var bestVariantURI string
	var maxBandwidth int

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Remove Session Keys and Program Date Time
		if strings.HasPrefix(trimmed, "#EXT-X-SESSION-KEY") || strings.HasPrefix(trimmed, "#EXT-X-PROGRAM-DATE-TIME") {
			continue
		}

		// Handle Stream Inf
		if strings.HasPrefix(trimmed, "#EXT-X-STREAM-INF") {
			bw := parseBandwidth(trimmed)
			if bw > maxBandwidth {
				maxBandwidth = bw
				bestVariant = line
				// The next line is the URI
				if i+1 < len(lines) {
					bestVariantURI = strings.TrimSpace(lines[i+1])
					i++ // Skip the URI line
				}
			} else {
				// Skip this variant and its URI
				if i+1 < len(lines) && !strings.HasPrefix(lines[i+1], "#") {
					i++
				}
			}
			continue
		}

		// Rewrite Stream URIs for other tags (like Media)
		if strings.HasPrefix(trimmed, "#") {
			// Check for URI attribute in tags like #EXT-X-MEDIA
			if strings.Contains(trimmed, "URI=\"") {
				line = rewriteURIAttribute(line, hexKey, baseURL)
			}
			fmt.Fprintln(w, line)
		} else if len(trimmed) > 0 {
			// This branch handles lines that are not tags and not variant URIs (since we handled those above)
			// This might be comments or unexpected content, just print it.
			fmt.Fprintln(w, line)
		} else {
			fmt.Fprintln(w, line)
		}
	}

	// Output the best variant
	if bestVariant != "" {
		fmt.Fprintln(w, bestVariant)
		absoluteURL := resolveURL(baseURL, bestVariantURI)
		proxyURL := fmt.Sprintf("/playlist.m3u8?url=%s&key=%s", url.QueryEscape(absoluteURL), hexKey)
		fmt.Fprintln(w, proxyURL)
	}
}

func processMediaPlaylist(w http.ResponseWriter, lines []string, base64Key, baseURL string) {
	keyInserted := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Remove existing keys and Program Date Time
		if strings.HasPrefix(trimmed, "#EXT-X-KEY") || strings.HasPrefix(trimmed, "#EXT-X-PROGRAM-DATE-TIME") {
			continue
		}

		// Insert new key after header
		if !keyInserted && strings.HasPrefix(trimmed, "#EXT") && !strings.HasPrefix(trimmed, "#EXTM3U") && !strings.HasPrefix(trimmed, "#EXT-X-VERSION") {
			// Insert before the first tag that isn't the header
			// Actually, usually keys come before segments. Let's put it after #EXT-X-VERSION or #EXT-X-TARGETDURATION or similar top level tags.
			// A safe bet is to insert it before the first segment or key-dependent tag.
			// But simpler: Insert it after the standard headers.
			// Let's just print it before printing the current line if it's the first non-header tag?
			// Or just insert it right after #EXTM3U or #EXT-X-VERSION if present.
			
			// Better strategy: Print it once we see the first tag that implies content or just after headers.
			// Let's print it immediately after #EXT-X-VERSION if it exists, or after #EXTM3U if not.
			// To be safe and simple: We'll just print it at the top of the loop if we haven't yet, but we need to respect the file order.
			// Wait, the user wants to replace keys.
			// Let's just insert it before the first segment or map.
		}
		
		// We will insert the key explicitly before the first segment or map, OR if we hit the end of headers.
		// Let's do this: Iterate, print headers. If we see a segment or map, and haven't printed key, print key.
		
		// Rewrite Map URI
		if strings.HasPrefix(trimmed, "#EXT-X-MAP") {
			if !keyInserted {
				printKey(w, base64Key)
				keyInserted = true
			}
			line = rewriteMapURI(line, baseURL)
		}

		// Rewrite Segment URI
		if !strings.HasPrefix(trimmed, "#") && len(trimmed) > 0 {
			if !keyInserted {
				printKey(w, base64Key)
				keyInserted = true
			}
			absoluteURL := resolveURL(baseURL, trimmed)
			fmt.Fprintln(w, absoluteURL)
			continue
		}

		// Handle Header insertion logic if not triggered by segment
		if !keyInserted && (strings.HasPrefix(trimmed, "#EXTINF") || strings.HasPrefix(trimmed, "#EXT-X-BYTERANGE")) {
			printKey(w, base64Key)
			keyInserted = true
		}

		fmt.Fprintln(w, line)
	}
}

func printKey(w http.ResponseWriter, base64Key string) {
	// Using identity format as requested in plan, but user asked for SAMPLE-AES.
	// User example: #EXT-X-SESSION-KEY:KEYFORMATVERSIONS="1",METHOD=SAMPLE-AES...
	// User request: "add the hex key as a SAMPLE-AES key line"
	// I will use KEYFORMAT="identity" usually for raw keys, but if they want SAMPLE-AES with a raw key, 
	// standard HLS uses METHOD=SAMPLE-AES,URI="data:..." and usually implicit identity or specified.
	// I'll stick to the plan: METHOD=SAMPLE-AES,URI="data:...",KEYFORMAT="identity"
	
	// Note: The user provided example shows KEYFORMAT="urn:uuid:..." and "com.microsoft.playready".
	// I will replace all that with a single key line.
	
	fmt.Fprintf(w, "#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"data:text/plain;base64,%s\",KEYFORMAT=\"identity\",KEYFORMATVERSIONS=\"1\"\n", base64Key)
}

func rewriteURIAttribute(line, hexKey, baseURL string) string {
	// Regex or simple string parsing. Simple parsing is faster and sufficient if format is standard.
	// We look for URI="..."
	// We need to replace the value inside quotes.
	
	// Find URI="
	start := strings.Index(line, "URI=\"")
	if start == -1 {
		return line
	}
	start += 5 // length of URI="

	end := strings.Index(line[start:], "\"")
	if end == -1 {
		return line
	}
	end += start

	originalURI := line[start:end]
	absoluteURL := resolveURL(baseURL, originalURI)
	
	// It's a playlist in a master playlist, so we proxy it.
	proxyURL := fmt.Sprintf("/playlist.m3u8?url=%s&key=%s", url.QueryEscape(absoluteURL), hexKey)

	return line[:start] + proxyURL + line[end:]
}

func rewriteMapURI(line, baseURL string) string {
	start := strings.Index(line, "URI=\"")
	if start == -1 {
		return line
	}
	start += 5

	end := strings.Index(line[start:], "\"")
	if end == -1 {
		return line
	}
	end += start

	originalURI := line[start:end]
	absoluteURL := resolveURL(baseURL, originalURI)

	return line[:start] + absoluteURL + line[end:]
}

func resolveURL(base, target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	// Handle absolute path relative to domain
	if strings.HasPrefix(target, "/") {
		u, _ := url.Parse(base)
		return u.Scheme + "://" + u.Host + target
	}
	return base + target
}

func parseBandwidth(line string) int {
	idx := strings.Index(line, "BANDWIDTH=")
	if idx == -1 {
		return 0
	}
	rest := line[idx+10:]
	end := strings.Index(rest, ",")
	if end == -1 {
		end = len(rest)
	}
	val := rest[:end]
	bw, _ := strconv.Atoi(strings.TrimSpace(val))
	return bw
}
