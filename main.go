package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type Config struct {
	Delay string `json:"delay"`
}

var (
	config      Config
	configMutex sync.RWMutex
	configFile  = "config.json"
)

func loadConfig() {
	configMutex.Lock()
	defer configMutex.Unlock()

	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("Could not read config file, using default delay 2.3")
		config.Delay = "2.3"
		return
	}

	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("Could not parse config file, using default delay 2.3")
		config.Delay = "2.3"
		return
	}
}

func saveConfig() error {
	configMutex.RLock()
	defer configMutex.RUnlock()

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configFile, data, 0644)
}

func main() {
	loadConfig()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/playlist.m3u8", proxyHandler)
	http.HandleFunc("/decrypt", decryptHandler)
	http.HandleFunc("/key.ts", keyHandler)
	http.HandleFunc("/ffmpeg", ffmpegHandler)
	http.HandleFunc("/settings", settingsHandler)
	http.HandleFunc("/", uiHandler)

	log.Printf("Starting HLS Proxy on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	hexKey := r.URL.Query().Get("key")
	experimental := r.URL.Query().Get("experimental") == "true"

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
		processMasterPlaylist(w, lines, hexKey, baseURL, experimental)
	} else {
		processMediaPlaylist(w, lines, base64Key, hexKey, baseURL, experimental)
	}
}

func processMasterPlaylist(w http.ResponseWriter, lines []string, hexKey, baseURL string, experimental bool) {
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
				line = rewriteURIAttribute(line, hexKey, baseURL, experimental)
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
		if experimental {
			proxyURL += "&experimental=true"
		}
		fmt.Fprintln(w, proxyURL)
	}
}

func processMediaPlaylist(w http.ResponseWriter, lines []string, base64Key, hexKey, baseURL string, experimental bool) {
	keyInserted := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Remove existing keys and Program Date Time
		if strings.HasPrefix(trimmed, "#EXT-X-KEY") || strings.HasPrefix(trimmed, "#EXT-X-PROGRAM-DATE-TIME") {
			continue
		}

		if experimental {
			// In experimental mode, we don't insert keys, we decrypt on the fly
			// Rewrite Map URI
			if strings.HasPrefix(trimmed, "#EXT-X-MAP") {
				line = rewriteMapURI(line, baseURL, hexKey, true)
				fmt.Fprintln(w, line)
				continue
			}

			// Rewrite Segment URI
			if !strings.HasPrefix(trimmed, "#") && len(trimmed) > 0 {
				absoluteURL := resolveURL(baseURL, trimmed)
				decryptURL := fmt.Sprintf("/decrypt?url=%s&key=%s", url.QueryEscape(absoluteURL), hexKey)
				fmt.Fprintln(w, decryptURL)
				continue
			}
		} else {
			// Standard Proxy Mode logic

			// Insert new key after header
			if !keyInserted && strings.HasPrefix(trimmed, "#EXT") && !strings.HasPrefix(trimmed, "#EXTM3U") && !strings.HasPrefix(trimmed, "#EXT-X-VERSION") {
				// We will insert the key explicitly before the first segment or map, OR if we hit the end of headers.
			}

			// Rewrite Map URI
			if strings.HasPrefix(trimmed, "#EXT-X-MAP") {
				if !keyInserted {
					printKey(w, hexKey)
					keyInserted = true
				}
				line = rewriteMapURI(line, baseURL, "", false)
			}

			// Rewrite Segment URI
			if !strings.HasPrefix(trimmed, "#") && len(trimmed) > 0 {
				if !keyInserted {
					printKey(w, hexKey)
					keyInserted = true
				}
				absoluteURL := resolveURL(baseURL, trimmed)
				fmt.Fprintln(w, absoluteURL)
				continue
			}

			// Handle Header insertion logic if not triggered by segment
			if !keyInserted && (strings.HasPrefix(trimmed, "#EXTINF") || strings.HasPrefix(trimmed, "#EXT-X-BYTERANGE")) {
				printKey(w, hexKey)
				keyInserted = true
			}
		}

		fmt.Fprintln(w, line)
	}
}

func printKey(w http.ResponseWriter, hexKey string) {
	// Using identity format as requested in plan, but user asked for SAMPLE-AES.
	// User example: #EXT-X-SESSION-KEY:KEYFORMATVERSIONS="1",METHOD=SAMPLE-AES...
	// User request: "add the hex key as a SAMPLE-AES key line"
	// I will use KEYFORMAT="identity" usually for raw keys, but if they want SAMPLE-AES with a raw key,
	// standard HLS uses METHOD=SAMPLE-AES,URI="data:..." and usually implicit identity or specified.
	// I'll stick to the plan: METHOD=SAMPLE-AES,URI="data:...",KEYFORMAT="identity"

	// Note: The user provided example shows KEYFORMAT="urn:uuid:..." and "com.microsoft.playready".
	// I will replace all that with a single key line.

	fmt.Fprintf(w, "#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"/key.ts?key=%s\",KEYFORMAT=\"identity\",KEYFORMATVERSIONS=\"1\"\n", hexKey)
}

func rewriteURIAttribute(line, hexKey, baseURL string, experimental bool) string {
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
	if experimental {
		proxyURL += "&experimental=true"
	}

	return line[:start] + proxyURL + line[end:]
}

func rewriteMapURI(line, baseURL, hexKey string, experimental bool) string {
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

	var newURI string
	if experimental {
		newURI = fmt.Sprintf("/decrypt?url=%s&key=%s", url.QueryEscape(absoluteURL), hexKey)
	} else {
		newURI = absoluteURL
	}

	return line[:start] + newURI + line[end:]
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

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	hexKey := r.URL.Query().Get("key")

	if targetURL == "" || hexKey == "" {
		http.Error(w, "Missing 'url' or 'key' query parameters", http.StatusBadRequest)
		return
	}

	// Construct ffmpeg command
	// ffmpeg -decryption_key <key> -i <url> -c copy -f mp4 -movflags frag_keyframe+empty_moov+default_base_moof pipe:1
	cmd := exec.Command("ffmpeg",
		"-decryption_key", hexKey,
		"-i", targetURL,
		"-c", "copy",
		"-f", "mp4",
		"-movflags", "frag_keyframe+empty_moov+default_base_moof",
		"pipe:1",
	)

	// Set output to response writer
	cmd.Stdout = w
	// Capture stderr for debugging
	cmd.Stderr = os.Stderr

	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := cmd.Run(); err != nil {
		log.Printf("FFmpeg failed: %v", err)
		// Note: If we already started writing to w, this error might not be visible to client as HTTP error
	}
}

func keyHandler(w http.ResponseWriter, r *http.Request) {
	hexKey := r.URL.Query().Get("key")
	if hexKey == "" {
		http.Error(w, "Missing 'key' query parameter", http.StatusBadRequest)
		return
	}

	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		http.Error(w, "Invalid hex key", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(keyBytes)
}

func ffmpegHandler(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("v")
	a := r.URL.Query().Get("a")

	if v == "" || a == "" {
		http.Error(w, "Missing 'v' (video) or 'a' (audio) query parameters", http.StatusBadRequest)
		return
	}

	configMutex.RLock()
	delay := config.Delay
	configMutex.RUnlock()

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Optimized for faster startup: -fflags +nobuffer -probesize 32 -analyzeduration 0
	script := fmt.Sprintf("#!/bin/sh\nexec ffmpeg \\\n-fflags +nobuffer -probesize 32 -thread_queue_size 1024 -analyzeduration 0 \\\n-i \"%s\" \\\n-itsoffset %s -thread_queue_size 1024 -i \"%s\" \\\n-map 0:v \\\n-map 1:a \\\n-c copy \\\n-f mpegts -", v, delay, a)
	fmt.Fprint(w, script)
}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		delay := r.FormValue("delay")
		if delay != "" {
			configMutex.Lock()
			config.Delay = delay
			configMutex.Unlock()
			if err := saveConfig(); err != nil {
				http.Error(w, "Failed to save config", http.StatusInternalServerError)
				return
			}
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func uiHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	configMutex.RLock()
	currentDelay := config.Delay
	configMutex.RUnlock()

	html := `<!DOCTYPE html>
<html>
<head>
    <title>FFmpeg Stream Mixer</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 20px auto; padding: 20px; }
        .section { margin-bottom: 30px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .field { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="number"] { width: 100%; padding: 8px; box-sizing: border-box; }
        .result { margin-top: 20px; padding: 15px; background: #f0f0f0; border: 1px solid #ccc; word-break: break-all; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        h2 { margin-top: 0; }
    </style>
</head>
<body>
    <h1>FFmpeg Stream Mixer</h1>
    
    <div class="section">
        <h2>Global Settings</h2>
        <form action="/settings" method="POST">
            <div class="field">
                <label for="globalDelay">Global Audio Delay (seconds):</label>
                <input type="number" id="globalDelay" name="delay" step="0.1" value="` + currentDelay + `">
            </div>
            <button type="submit">Save Delay</button>
        </form>
    </div>

    <div class="section">
        <h2>Generate Stream Link</h2>
        <div class="field">
            <label for="videoUrl">Video URL (m3u8):</label>
            <input type="text" id="videoUrl" placeholder="https://example.com/video.m3u8">
        </div>
        <div class="field">
            <label for="audioUrl">Audio URL (aac/m3u8):</label>
            <input type="text" id="audioUrl" placeholder="https://example.com/audio.aac">
        </div>
        <button onclick="generateLink()">Generate Stream Link</button>

        <div id="resultContainer" style="display:none;">
            <h3>Stream URL:</h3>
            <div class="result" id="streamUrl"></div>
            <p><small>Open this URL in VLC or any player that supports MPEG-TS over HTTP.</small></p>
            <p><small>Note: Delay is now persisted globally on the server.</small></p>
        </div>
    </div>

    <script>
        function generateLink() {
            const v = encodeURIComponent(document.getElementById('videoUrl').value);
            const a = encodeURIComponent(document.getElementById('audioUrl').value);
            
            if (!v || !a) {
                alert('Please provide both video and audio URLs');
                return;
            }

            const streamUrl = window.location.origin + '/ffmpeg?v=' + v + '&a=' + a;
            document.getElementById('streamUrl').innerText = streamUrl;
            document.getElementById('resultContainer').style.display = 'block';
        }
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}
