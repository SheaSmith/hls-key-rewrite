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
	"time"
)

type Stream struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	VideoURL   string  `json:"video_url"`
	VideoKey   string  `json:"video_key,omitempty"`
	AudioURL   string  `json:"audio_url"`
	AudioKey   string  `json:"audio_key,omitempty"`
	AudioDelay float64 `json:"audio_delay"` // in seconds
}

var (
	streams     = make(map[string]Stream)
	streamsLock sync.RWMutex
	streamsFile = "streams.json"
)

func main() {
	loadStreams()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/playlist.m3u8", proxyHandler)
	http.HandleFunc("/decrypt", decryptHandler)
	http.HandleFunc("/key.ts", keyHandler)

	// New system endpoints
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/api/streams", apiStreamsHandler)
	http.HandleFunc("/tvheadend.m3u8", tvheadendPlaylistHandler)
	http.HandleFunc("/stream/", streamM3UHandler)

	log.Printf("Starting HLS Proxy on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func loadStreams() {
	file, err := os.ReadFile(streamsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.Printf("Failed to read streams file: %v", err)
		return
	}
	streamsLock.Lock()
	defer streamsLock.Unlock()
	if err := json.Unmarshal(file, &streams); err != nil {
		log.Printf("Failed to unmarshal streams: %v", err)
	}
}

func saveStreams() {
	streamsLock.RLock()
	defer streamsLock.RUnlock()
	data, err := json.MarshalIndent(streams, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal streams: %v", err)
		return
	}
	if err := os.WriteFile(streamsFile, data, 0644); err != nil {
		log.Printf("Failed to save streams: %v", err)
	}
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	const adminHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Stream Manager</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        input[type="text"], input[type="number"] { width: 100%; box-sizing: border-box; }
        .actions { white-space: nowrap; }
        .export-import { margin-top: 20px; border-top: 1px solid #ccc; padding-top: 10px; }
    </style>
</head>
<body>
    <h1>Stream Manager</h1>
    <div id="app">
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Video URL</th>
                    <th>Video Key (Hex)</th>
                    <th>Audio URL (HLS/AAC)</th>
                    <th>Audio Key (Hex)</th>
                    <th>Delay (sec)</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="stream-list"></tbody>
            <tfoot>
                <tr>
                    <td><input type="text" id="new-name" placeholder="Name"></td>
                    <td><input type="text" id="new-video-url" placeholder="Video URL"></td>
                    <td><input type="text" id="new-video-key" placeholder="Hex Key"></td>
                    <td><input type="text" id="new-audio-url" placeholder="Audio URL"></td>
                    <td><input type="text" id="new-audio-key" placeholder="Hex Key"></td>
                    <td><input type="number" id="new-delay" value="0" step="0.1"></td>
                    <td><button onclick="addStream()">Add</button></td>
                </tr>
            </tfoot>
        </table>

        <div class="export-import">
            <h3>Import/Export</h3>
            <button onclick="exportStreams()">Export JSON</button>
            <input type="file" id="import-file" accept=".json" onchange="importStreams(event)">
        </div>
    </div>

    <script>
        async function loadStreams() {
            const resp = await fetch('/api/streams');
            const streams = await resp.json();
            const list = document.getElementById('stream-list');
            list.innerHTML = '';
            Object.values(streams).forEach(s => {
                const tr = document.createElement('tr');
                tr.innerHTML = ` + "`" + `
                    <td><input type="text" value="${s.name}" onchange="updateStream('${s.id}', 'name', this.value)"></td>
                    <td><input type="text" value="${s.video_url}" onchange="updateStream('${s.id}', 'video_url', this.value)"></td>
                    <td><input type="text" value="${s.video_key || ''}" onchange="updateStream('${s.id}', 'video_key', this.value)"></td>
                    <td><input type="text" value="${s.audio_url}" onchange="updateStream('${s.id}', 'audio_url', this.value)"></td>
                    <td><input type="text" value="${s.audio_key || ''}" onchange="updateStream('${s.id}', 'audio_key', this.value)"></td>
                    <td><input type="number" value="${s.audio_delay}" step="0.1" onchange="updateStream('${s.id}', 'audio_delay', parseFloat(this.value))"></td>
                    <td class="actions">
                        <button onclick="deleteStream('${s.id}')">Delete</button>
                        <a href="/playlist.m3u8?url=${encodeURIComponent(s.video_url)}&key=${s.video_key || ''}" target="_blank">Video</a>
                        <a href="/playlist.m3u8?url=${encodeURIComponent(s.audio_url)}&key=${s.audio_key || ''}" target="_blank">Audio</a>
                    </td>
                ` + "`" + `;
                list.appendChild(tr);
            });
        }

        async function addStream() {
            const stream = {
                name: document.getElementById('new-name').value,
                video_url: document.getElementById('new-video-url').value,
                video_key: document.getElementById('new-video-key').value,
                audio_url: document.getElementById('new-audio-url').value,
                audio_key: document.getElementById('new-audio-key').value,
                audio_delay: parseFloat(document.getElementById('new-delay').value)
            };
            await fetch('/api/streams', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(stream)
            });
            loadStreams();
        }

        async function updateStream(id, field, value) {
            const resp = await fetch('/api/streams');
            const streams = await resp.json();
            const stream = streams[id];
            stream[field] = value;
            await fetch('/api/streams', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(stream)
            });
        }

        async function deleteStream(id) {
            if (confirm('Delete stream?')) {
                await fetch('/api/streams?id=' + id, { method: 'DELETE' });
                loadStreams();
            }
        }

        function exportStreams() {
            fetch('/api/streams')
                .then(resp => resp.json())
                .then(streams => {
                    const blob = new Blob([JSON.stringify(streams, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'streams.json';
                    a.click();
                });
        }

        function importStreams(event) {
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = async (e) => {
                const streams = JSON.parse(e.target.result);
                await fetch('/api/streams', {
                    method: 'IMPORT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(streams)
                });
                loadStreams();
            };
            reader.readAsText(file);
        }

        loadStreams();
    </script>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(adminHTML))
}

func apiStreamsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		streamsLock.RLock()
		defer streamsLock.RUnlock()
		json.NewEncoder(w).Encode(streams)
	case "POST", "PUT":
		var s Stream
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if s.ID == "" {
			s.ID = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		streamsLock.Lock()
		streams[s.ID] = s
		streamsLock.Unlock()
		saveStreams()
		w.WriteHeader(http.StatusOK)
	case "DELETE":
		id := r.URL.Query().Get("id")
		streamsLock.Lock()
		delete(streams, id)
		streamsLock.Unlock()
		saveStreams()
		w.WriteHeader(http.StatusOK)
	case "IMPORT":
		var imported map[string]Stream
		if err := json.NewDecoder(r.Body).Decode(&imported); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		streamsLock.Lock()
		for k, v := range imported {
			streams[k] = v
		}
		streamsLock.Unlock()
		saveStreams()
		w.WriteHeader(http.StatusOK)
	}
}

func streamM3UHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/stream/")
	id = strings.TrimSuffix(id, ".m3u8")
	id = strings.TrimSuffix(id, ".m3u")

	streamsLock.RLock()
	s, ok := streams[id]
	streamsLock.RUnlock()

	if !ok {
		http.Error(w, "Stream not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-mpegurl")
	fmt.Fprintln(w, "#EXTM3U")
	fmt.Fprintf(w, "#EXTINF:-1, %s\n", s.Name)
	fmt.Fprintf(w, "pipe://%s\n", generateFFmpegCommand(s, r.Host))
}

func generateFFmpegCommand(s Stream, host string) string {
	videoURL := s.VideoURL
	if s.VideoKey != "" {
		videoURL = fmt.Sprintf("https://%s/playlist.m3u8?url=%s&key=%s&experimental=true", host, url.QueryEscape(s.VideoURL), s.VideoKey)
	}

	audioURL := s.AudioURL
	if s.AudioKey != "" {
		audioURL = fmt.Sprintf("https://%s/playlist.m3u8?url=%s&key=%s&experimental=true", host, url.QueryEscape(s.AudioURL), s.AudioKey)
	}

	delay := s.AudioDelay

	// TVHeadend prefers mpegts for pipes.
	// Re-encoding audio to AAC ensures it plays back nicely with TVHeadend and handles delay correctly.
	return fmt.Sprintf("ffmpeg -i \"%s\" -itsoffset %f -i \"%s\" -map 0:v -map 1:a -c:v copy -c:a aac -f mpegts pipe:1", videoURL, delay, audioURL)
}

func tvheadendPlaylistHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-mpegurl")
	fmt.Fprintln(w, "#EXTM3U")
	streamsLock.RLock()
	defer streamsLock.RUnlock()

	host := r.Host
	if host == "" {
		host = "localhost:8080"
	}

	for _, s := range streams {
		fmt.Fprintf(w, "#EXTINF:-1, %s\n", s.Name)
		fmt.Fprintf(w, "https://%s/stream/%s.m3u\n", host, s.ID)
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
