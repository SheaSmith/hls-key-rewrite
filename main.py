import requests
import m3u8
from m3u8.model import SessionKey
from flask import Flask, Response, request, stream_with_context
from urllib.parse import urljoin, quote
import base64
import re
from io import BytesIO
from typing import Optional
from Crypto.Cipher import AES

app = Flask(__name__)

@app.route("/key")
def serve_key():
    key_hex = request.args.get("key")
    if not key_hex:
        return "missing key", 400

    key_bytes = bytes.fromhex(key_hex)
    return Response(key_bytes, content_type="application/octet-stream")

@app.route("/playlist.m3u8")
def playlist():
    hls_url = request.args.get("url")
    key_hex = request.args.get("key")
    decrypt = request.args.get("decrypt")  # e.g. 'cbcs' to enable on-the-fly decryption
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

    # Make EXT-X-MAP URIs absolute or proxy through /segment if decrypt is requested
    def rewrite_map(match):
        rel_uri = match.group(1)
        abs_uri = urljoin(hls_url, rel_uri)
        if decrypt == "cbcs":
            prox = f"/segment?url={quote(abs_uri)}&key={key_hex}&decrypt=cbcs"
            return f'#EXT-X-MAP:URI="{prox}"'
        return f'#EXT-X-MAP:URI="{abs_uri}"'
    playlist_text = re.sub(r'#EXT-X-MAP:URI="([^"]+)"', rewrite_map, playlist_text)

    # Parse playlist with m3u8 for further processing
    playlist = m3u8.loads(playlist_text, uri=hls_url)

    key_uri = f"http://{request.host}/key?key={key_hex}"

    # Replace/remove any EXT-X-SESSION-KEY entries in master depending on decrypt flag
    if hasattr(playlist, "session_keys") and playlist.session_keys is not None:
        if decrypt == "cbcs":
            # When decrypting on proxy, strip session keys entirely
            playlist.session_keys = []
        else:
            # Overwrite with a single identity key that points to our /key endpoint
            playlist.session_keys = [
                SessionKey(
                    method="SAMPLE-AES",  # adjust if upstream uses CTR
                    uri=key_uri,
                    keyformat="identity",
                    base_uri=hls_url,
                )
            ]

    # Replace or remove all EXT-X-KEY tags depending on decrypt flag
    if decrypt == "cbcs":
        # Remove keys entirely so players don't try to fetch keys client-side
        try:
            playlist.keys = []
        except Exception:
            # Fallback: ignore if structure differs
            pass
    else:
        for key_tag in playlist.keys:
            if key_tag:
                key_tag.uri = key_uri
                key_tag.method = "SAMPLE-AES"  # change if CTR
                key_tag.keyformat = "identity"

    # Master playlist: rewrite variant URIs and EXT-X-MEDIA
    if playlist.is_variant:
        for v in playlist.playlists:
            abs_url = urljoin(hls_url, v.uri)
            if decrypt == "cbcs":
                v.uri = f"/playlist.m3u8?url={quote(abs_url)}&key={key_hex}&decrypt=cbcs"
            else:
                v.uri = f"/playlist.m3u8?url={quote(abs_url)}&key={key_hex}"
        for media in playlist.media:
            if media.uri:
                abs_url = urljoin(hls_url, media.uri)
                if media.type.lower() == "subtitles" or media.uri.endswith(".vtt"):
                    media.uri = abs_url
                else:
                    if decrypt == "cbcs":
                        media.uri = f"/playlist.m3u8?url={quote(abs_url)}&key={key_hex}&decrypt=cbcs"
                    else:
                        media.uri = f"/playlist.m3u8?url={quote(abs_url)}&key={key_hex}"
    else:
        # Rewrite segment URLs to absolute
        for seg in playlist.segments:
            abs_seg = urljoin(hls_url, seg.uri)
            if decrypt == "cbcs":
                seg.uri = f"/segment?url={quote(abs_seg)}&key={key_hex}&decrypt=cbcs"
            else:
                seg.uri = abs_seg

    # Dump playlist text
    out_text = playlist.dumps()
    # As a safety net, strip any remaining key tags when decrypting
    if decrypt == "cbcs":
        out_text = re.sub(r"(?mi)^#EXT-X-KEY:.*\n", "", out_text)
        out_text = re.sub(r"(?mi)^#EXT-X-SESSION-KEY:.*\n", "", out_text)

    return Response(out_text, content_type="application/vnd.apple.mpegurl")


def _read_u32(b: BytesIO) -> int:
    return int.from_bytes(b.read(4), "big")


def _read_box(stream: BytesIO):
    start = stream.tell()
    size_bytes = stream.read(4)
    if len(size_bytes) < 4:
        return None
    size = int.from_bytes(size_bytes, "big")
    typ = stream.read(4)
    if len(typ) < 4:
        return None
    if size == 1:
        largesize = int.from_bytes(stream.read(8), "big")
        size = largesize
        header = 16
    else:
        header = 8
    if size == 0:
        # to EOF
        data = stream.read()
        return (typ.decode('ascii'), start, header, len(data) + header, data)
    data_size = size - header
    data = stream.read(data_size)
    return (typ.decode('ascii'), start, header, size, data)


def _find_boxes(data: bytes, path: list[str]):
    # simple depth-first search by types path
    results = []
    def walk(buf: bytes, depth: int):
        s = BytesIO(buf)
        while True:
            pos = s.tell()
            box = _read_box(s)
            if not box:
                break
            typ, start, header, size, payload = box
            if typ == path[depth]:
                if depth == len(path) - 1:
                    results.append((pos, header, size, payload))
                else:
                    # descend
                    walk(payload, depth + 1)
    walk(data, 0)
    return results


def _parse_senc(payload: bytes):
    bio = BytesIO(payload)
    version = int.from_bytes(bio.read(1), 'big')
    flags = int.from_bytes(bio.read(3), 'big')
    sample_count = _read_u32(bio)
    ivs = []
    subsamples_present = (flags & 0x0002) != 0
    for _ in range(sample_count):
        iv = bio.read(16)  # assume 16-byte IV
        ivs.append(iv)
        if subsamples_present:
            # skip subsample encryption info for MVP
            num = int.from_bytes(bio.read(2), 'big')
            for _j in range(num):
                _clear = _read_u32(bio)
                _enc = _read_u32(bio)
    return ivs


def _parse_trun(payload: bytes):
    bio = BytesIO(payload)
    version = int.from_bytes(bio.read(1), 'big')
    flags = int.from_bytes(bio.read(3), 'big')
    sample_count = _read_u32(bio)
    data_offset = None
    if flags & 0x000001:
        # signed
        val = _read_u32(bio)
        if val & 0x80000000:
            val = -((~val & 0xFFFFFFFF) + 1)
        data_offset = val
    if flags & 0x000004:
        _ = _read_u32(bio)  # first_sample_flags
    has_size = (flags & 0x000200) != 0
    sizes = []
    for _ in range(sample_count):
        if has_size:
            sizes.append(_read_u32(bio))
        else:
            # unknown – fallback: empty; caller must ignore
            sizes.append(0)
        if flags & 0x000100:
            _ = _read_u32(bio)  # duration
        if flags & 0x000400:
            _ = _read_u32(bio)  # sample flags
        if flags & 0x000800:
            _ = _read_u32(bio)  # cto
    return sizes, data_offset


def _cbcs_decrypt_sample(sample: bytes, key: bytes, iv: bytes) -> bytes:
    # Pattern: encrypt first block out of each 10-block group (1:9). Others are clear.
    out = bytearray(len(sample))
    aes = AES.new(key, AES.MODE_ECB)  # we'll implement CBC manually
    prev = iv
    total_blocks = len(sample) // 16
    offset = 0
    for b in range(total_blocks):
        block = sample[offset:offset+16]
        if (b % 10) == 0:
            # decrypt CBC: P = D_K(C) xor prev
            dec = aes.decrypt(block)
            pblk = bytes(x ^ y for x, y in zip(dec, prev))
            out[offset:offset+16] = pblk
            prev = block  # CBC chain updates only on encrypted blocks
        else:
            # pass-through clear block
            out[offset:offset+16] = block
            # prev remains unchanged across clear blocks in cbcs
        offset += 16
    # tail bytes (not full block) are clear
    tail = sample[offset:]
    if tail:
        out[offset:] = tail
    return bytes(out)


def decrypt_cbcs_fmp4(segment: bytes, key: bytes) -> bytes:
    # Very simplified CMAF decrypter: assumes single track, per-sample IVs in senc, no subsamples,
    # trun provides per-sample sizes, and data flows sequentially in mdat.
    bio = BytesIO(segment)
    # Find moof and mdat payloads
    moof_boxes = []
    mdat_payload = None
    # top-level walk
    while True:
        here = bio.tell()
        box = _read_box(bio)
        if not box:
            break
        typ, start, header, size, payload = box
        if typ == 'moof':
            moof_boxes.append(payload)
        if typ == 'mdat':
            mdat_payload = (start, header, size, payload)
    if not moof_boxes or not mdat_payload:
        return segment  # not fMP4 segment

    # Collect IVs and sample sizes from first traf
    ivs = []
    sizes = []
    for moof in moof_boxes:
        # find traf boxes
        trafs = _find_boxes(moof, ['traf'])
        for _, _, _, traf_payload in trafs:
            # senc inside traf (possibly under 'uuid' for PIFF, we expect 'senc')
            sencs = _find_boxes(traf_payload, ['senc'])
            if not sencs:
                continue
            ivs.extend(_parse_senc(sencs[0][3]))
            # trun boxes carry sample sizes
            truns = _find_boxes(traf_payload, ['trun'])
            for tr in truns:
                s, _off = _parse_trun(tr[3])
                sizes.extend(s)
    if not ivs or not sizes:
        return segment
    sample_count = min(len(ivs), len(sizes))

    # Decrypt samples in-place over mdat payload
    mdat_start, mdat_header, mdat_size, mdat_data = mdat_payload
    mdat_bytes = bytearray(mdat_data)
    ptr = 0
    for i in range(sample_count):
        sz = sizes[i]
        if sz <= 0 or ptr + sz > len(mdat_bytes):
            break
        sample_bytes = bytes(mdat_bytes[ptr:ptr+sz])
        dec = _cbcs_decrypt_sample(sample_bytes, key, ivs[i])
        mdat_bytes[ptr:ptr+sz] = dec
        ptr += sz

    # Rebuild file: We replace the original mdat payload with decrypted payload
    # Simplify: return original up to mdat header, then decrypted mdat payload, then any remaining boxes
    # Reconstruct by scanning again to get positions
    full = bytearray(segment)
    # find first 'mdat' header position to replace payload
    s = BytesIO(segment)
    while True:
        pos = s.tell()
        box = _read_box(s)
        if not box:
            break
        typ, start, header, size, payload = box
        if typ == 'mdat':
            payload_pos = pos + header
            full[payload_pos:payload_pos+len(mdat_bytes)] = mdat_bytes
            return bytes(full)
    return segment


@app.route("/segment")
def segment():
    url = request.args.get("url")
    key_hex = request.args.get("key")
    decrypt = request.args.get("decrypt")
    if not url:
        return "Missing url", 400
    # Fetch upstream segment fully for MVP
    upstream = requests.get(url, stream=False)
    upstream.raise_for_status()
    content = upstream.content
    content_type = upstream.headers.get('Content-Type', 'application/octet-stream')

    if decrypt == "cbcs":
        try:
            key = bytes.fromhex(key_hex) if key_hex else None
            if not key or len(key) != 16:
                return Response(content, content_type=content_type)
            decrypted = decrypt_cbcs_fmp4(content, key)
            return Response(decrypted, content_type=content_type)
        except Exception:
            # Fallback to pass-through on errors (experimental feature)
            return Response(content, content_type=content_type)

    return Response(content, content_type=content_type)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
