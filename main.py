import requests
import m3u8
from flask import Flask, Response, request
from urllib.parse import urljoin, quote
import base64
import re

app = Flask(__name__)

@app.route("/playlist.m3u8")
def playlist():
    hls_url = request.args.get("url")
    key_hex = request.args.get("key")
    if not hls_url or not key_hex:
        return "Missing url or key", 400

    # Convert key to base64 for data URI
    key_bytes = bytes.fromhex(key_hex)
    key_b64 = base64.b64encode(key_bytes).decode("utf-8")
    data_uri = f"data:text/plain;base64,{key_b64}"

    # Fetch upstream playlist
    r = requests.get(hls_url)
    r.raise_for_status()
    playlist_text = r.text

    # Make EXT-X-MAP URIs absolute (_init.mp4)
    def map_absolute(match):
        rel_uri = match.group(1)
        abs_uri = urljoin(hls_url, rel_uri)
        return f'#EXT-X-MAP:URI="{abs_uri}"'
    playlist_text = re.sub(r'#EXT-X-MAP:URI="([^"]+)"', map_absolute, playlist_text)

    # Parse playlist with m3u8 for further processing
    playlist = m3u8.loads(playlist_text, uri=hls_url)

    # Replace all EXT-X-KEY tags with data URI
    for key_tag in playlist.keys:
        if key_tag:
            key_tag.uri = data_uri
            key_tag.method = "SAMPLE-AES-CBC"  # change if CTR
            key_tag.keyformat = "identity"

    # Master playlist: rewrite variant URIs and EXT-X-MEDIA
    if playlist.is_variant:
        for v in playlist.playlists:
            abs_url = urljoin(hls_url, v.uri)
            v.uri = f"/playlist.m3u8?url={quote(abs_url)}&key={key_hex}"
        for media in playlist.media:
            if media.uri:
                abs_url = urljoin(hls_url, media.uri)
                if media.type.lower() == "subtitles" or media.uri.endswith(".vtt"):
                    media.uri = abs_url
                else:
                    media.uri = f"/playlist.m3u8?url={quote(abs_url)}&key={key_hex}"
    else:
        # Rewrite segment URLs to absolute
        for seg in playlist.segments:
            seg.uri = urljoin(hls_url, seg.uri)

    return Response(playlist.dumps(), content_type="application/vnd.apple.mpegurl")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
