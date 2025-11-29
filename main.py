import requests
import m3u8
from m3u8.model import SessionKey
from flask import Flask, Response, request, stream_with_context
from urllib.parse import urljoin, quote
import base64
import re
from io import BytesIO
from typing import Optional, List, Tuple, Dict, Any
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
                    method="SAMPLE-AES-CBC",  # adjust if upstream uses CTR
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
                key_tag.method = "SAMPLE-AES-CBC"  # change if CTR
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


def _find_all_boxes(data: bytes, boxtype: str) -> List[Tuple[int, int, int, bytes]]:
    # Recursively find all boxes of a given type at any depth
    out: List[Tuple[int, int, int, bytes]] = []
    def walk(buf: bytes):
        s = BytesIO(buf)
        while True:
            pos = s.tell()
            box = _read_box(s)
            if not box:
                break
            typ, start, header, size, payload = box
            if typ == boxtype:
                out.append((pos, header, size, payload))
            # Always descend; if this box isn't a container, inner walk will end quickly
            walk(payload)
    walk(data)
    return out


def _parse_saiz(payload: bytes) -> Tuple[int, List[int]]:
    # ISO/IEC 14496-12 Sample Auxiliary Information Sizes Box
    b = BytesIO(payload)
    version = int.from_bytes(b.read(1), 'big')
    flags = int.from_bytes(b.read(3), 'big')
    # aux_info_type and parameter are present if flags & 1
    if flags & 1:
        _aux_info_type = b.read(4)
        _aux_info_param = b.read(4)
    default_size = int.from_bytes(b.read(1), 'big')
    count = _read_u32(b)
    sizes: List[int] = []
    if default_size == 0:
        for _ in range(count):
            sizes.append(int.from_bytes(b.read(1), 'big'))
    else:
        sizes = [default_size] * count
    return default_size, sizes


def _parse_saio(payload: bytes) -> List[int]:
    # ISO/IEC 14496-12 Sample Auxiliary Information Offsets Box
    b = BytesIO(payload)
    version = int.from_bytes(b.read(1), 'big')
    flags = int.from_bytes(b.read(3), 'big')
    # aux_info_type and parameter are present if flags & 1
    if flags & 1:
        _aux_info_type = b.read(4)
        _aux_info_param = b.read(4)
    count = _read_u32(b)
    offs: List[int] = []
    if version == 0:
        for _ in range(count):
            offs.append(_read_u32(b))
    else:
        for _ in range(count):
            offs.append(int.from_bytes(b.read(8), 'big'))
    return offs


def _parse_aux_info_stream(buf: bytes, sample_count: int, iv_size_hint: int = 16) -> Tuple[List[bytes], List[Optional[List[Tuple[int, int]]]]]:
    """
    Parse a concatenated aux info stream (as addressed by saiz/saio) into per-sample IVs and subsamples.
    We try with iv_size_hint first; if parsing overruns, we retry with 8.
    """
    def try_parse(iv_size_local: int) -> Tuple[bool, List[bytes], List[Optional[List[Tuple[int, int]]]]]:
        ivs: List[bytes] = []
        subs: List[Optional[List[Tuple[int, int]]]] = []
        s = BytesIO(buf)
        try:
            for _ in range(sample_count):
                iv = s.read(iv_size_local)
                if len(iv) < iv_size_local:
                    return False, [], []
                if iv_size_local == 8:
                    iv = iv + b"\x00" * 8
                # If there's still data, it may have subsamples
                # Not all samples will have subsamples; but when present the layout is: u16 count then pairs
                # Peek next 2 bytes; if buffer exhausted or sizes do not align, treat as no subsamples
                pos = s.tell()
                next2 = s.read(2)
                if len(next2) < 2:
                    ivs.append(iv)
                    subs.append(None)
                    continue
                subcnt = int.from_bytes(next2, 'big')
                # Heuristic: if subcnt is small and enough bytes remain, parse pairs; else rewind
                need = subcnt * 8
                rem = len(buf) - s.tell()
                if subcnt > 0 and rem >= need:
                    pairs: List[Tuple[int, int]] = []
                    for _j in range(subcnt):
                        clear_b = _read_u32(s)
                        enc_b = _read_u32(s)
                        pairs.append((clear_b, enc_b))
                    ivs.append(iv)
                    subs.append(pairs)
                else:
                    # rewind and treat as no subsamples for this sample
                    s.seek(pos)
                    ivs.append(iv)
                    subs.append(None)
            return True, ivs, subs
        except Exception:
            return False, [], []

    ok, ivs, subs = try_parse(iv_size_hint)
    if not ok and iv_size_hint == 16:
        ok, ivs, subs = try_parse(8)
    if not ok:
        return [], []
    return ivs, subs


def _parse_senc(payload: bytes, iv_size: int = 16) -> Tuple[List[bytes], List[Optional[List[Tuple[int, int]]]], bool]:
    # Returns: (ivs, subsamples_list, subsamples_present)
    bio = BytesIO(payload)
    version = int.from_bytes(bio.read(1), 'big')
    flags = int.from_bytes(bio.read(3), 'big')
    sample_count = _read_u32(bio)
    ivs: List[bytes] = []
    subsamples_present = (flags & 0x0002) != 0
    subs: List[Optional[List[Tuple[int, int]]]] = []
    for _ in range(sample_count):
        iv = bio.read(iv_size)
        if len(iv) < iv_size:
            # malformed; pad
            iv = (iv or b"") + b"\x00" * (iv_size - len(iv or b""))
        if iv_size == 8:
            iv = iv + b"\x00" * 8
    ivs.append(iv)
    if subsamples_present:
        num = int.from_bytes(bio.read(2), 'big')
        pairs: List[Tuple[int, int]] = []
        for _j in range(num):
            clear_bytes = _read_u32(bio)
            enc_bytes = _read_u32(bio)
            pairs.append((clear_bytes, enc_bytes))
        subs.append(pairs)
    else:
        subs.append(None)
    return ivs, subs, subsamples_present


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


def _cbcs_decrypt_region(region: bytes, aes: AES, prev: bytes, crypt: int, skip: int) -> Tuple[bytes, bytes]:
    # Decrypt a contiguous encrypted region using cbcs pattern (crypt:skip blocks)
    # Only full 16-byte blocks are processed; partial tail remains as-is per spec.
    out = bytearray(len(region))
    total_blocks = len(region) // 16
    offset = 0
    # group size
    g = max(1, crypt + skip)
    for b in range(total_blocks):
        block = region[offset:offset+16]
        in_crypt = (b % g) < crypt
        if in_crypt:
            dec = aes.decrypt(block)
            pblk = bytes(x ^ y for x, y in zip(dec, prev))
            out[offset:offset+16] = pblk
            prev = block  # CBC chain only updates on encrypted blocks
        else:
            out[offset:offset+16] = block
            # prev unchanged on skipped blocks
        offset += 16
    # copy any tail bytes (not full block)
    if offset < len(region):
        out[offset:] = region[offset:]
    return bytes(out), prev

def _cbcs_decrypt_full_sample(sample: bytes, key: bytes, iv: bytes, crypt: int, skip: int,
                              subsamples: Optional[List[Tuple[int, int]]] = None) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    prev = iv
    if not subsamples:
        dec, _prev = _cbcs_decrypt_region(sample, aes, prev, crypt, skip)
        return dec
    # With subsamples: sequence of clear/encrypted byte counts
    out = bytearray(len(sample))
    ptr = 0
    for clear_b, enc_b in subsamples:
        if clear_b:
            out[ptr:ptr+clear_b] = sample[ptr:ptr+clear_b]
            ptr += clear_b
        if enc_b:
            region = sample[ptr:ptr+enc_b]
            dec_region, prev = _cbcs_decrypt_region(region, aes, prev, crypt, skip)
            out[ptr:ptr+enc_b] = dec_region
            ptr += enc_b
    # copy any trailing bytes (shouldn't exist per spec, but be safe)
    out[ptr:] = sample[ptr:]
    return bytes(out)


def decrypt_cbcs_fmp4(segment: bytes, key: bytes,
                      default_iv_size: int = 16,
                      pattern: Tuple[int, int] = (1, 9)) -> bytes:
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

    # Collect IVs, subsample info and sample sizes
    ivs: List[bytes] = []
    subs_list: List[Optional[List[Tuple[int, int]]]] = []
    sizes: List[int] = []
    # Track absolute payload start of first mdat for offset heuristics
    mdat_abs_payload_pos = None
    # Compute absolute payload position of the first mdat
    sscan = BytesIO(segment)
    while True:
        pos = sscan.tell()
        box = _read_box(sscan)
        if not box:
            break
        typ, start, header, size, payload = box
        if typ == 'mdat':
            mdat_abs_payload_pos = pos + header
            break

    for moof in moof_boxes:
        # find traf boxes
        trafs = _find_boxes(moof, ['traf'])
        for _, _, _, traf_payload in trafs:
            # trun boxes carry sample sizes
            truns = _find_boxes(traf_payload, ['trun'])
            traf_sizes: List[int] = []
            for tr in truns:
                ssz, _off = _parse_trun(tr[3])
                traf_sizes.extend(ssz)

            # Prefer inline senc
            ivs_part: List[bytes] = []
            subs_part: List[Optional[List[Tuple[int, int]]]] = []
            sencs = _find_boxes(traf_payload, ['senc'])
            if sencs:
                try:
                    ivs_part, subs_part, _subs_present = _parse_senc(sencs[0][3], iv_size=default_iv_size)
                    if not ivs_part and default_iv_size == 16:
                        ivs_part, subs_part, _ = _parse_senc(sencs[0][3], iv_size=8)
                except Exception:
                    ivs_part, subs_part = [], []
            # If no inline senc, try saiz/saio
            if not ivs_part and traf_sizes:
                saizs = _find_boxes(traf_payload, ['saiz'])
                saios = _find_boxes(traf_payload, ['saio'])
                if saizs and saios:
                    try:
                        default_sz, entry_sizes = _parse_saiz(saizs[0][3])
                        offsets = _parse_saio(saios[0][3])
                        # Commonly a single base offset
                        if offsets:
                            base_off = offsets[0]
                            # Heuristics to resolve absolute offset
                            candidates = [base_off]
                            if mdat_abs_payload_pos is not None:
                                candidates.append(mdat_abs_payload_pos + base_off)
                            # moof-relative not precisely known; skip adding
                            aux_buf = None
                            for off in candidates:
                                if 0 <= off < len(segment):
                                    # Ensure we don't run past EOF; take enough bytes to cover all entries
                                    # Estimate needed size: sum(entry_sizes) or default*count
                                    need = sum(entry_sizes) if default_sz == 0 else default_sz * len(entry_sizes)
                                    if off + need <= len(segment):
                                        aux_buf = segment[off:off+need]
                                        break
                            if aux_buf is None and mdat_abs_payload_pos is not None:
                                # Fallback: clamp within mdat
                                start_off = mdat_abs_payload_pos
                                end_off = len(segment)
                                aux_buf = segment[start_off:end_off]
                            if aux_buf is not None:
                                ivs_part, subs_part = _parse_aux_info_stream(aux_buf, len(traf_sizes), iv_size_hint=default_iv_size)
                    except Exception:
                        ivs_part, subs_part = [], []

            # Append traf results
            sizes.extend(traf_sizes)
            ivs.extend(ivs_part)
            subs_list.extend(subs_part)
    if not ivs or not sizes:
        return segment
    sample_count = min(len(ivs), len(sizes))

    # Decrypt samples in-place over mdat payload
    mdat_start, mdat_header, mdat_size, mdat_data = mdat_payload
    mdat_bytes = bytearray(mdat_data)
    ptr = 0
    crypt, skip = pattern
    for i in range(sample_count):
        sz = sizes[i]
        if sz <= 0 or ptr + sz > len(mdat_bytes):
            break
        sample_bytes = bytes(mdat_bytes[ptr:ptr+sz])
        dec = _cbcs_decrypt_full_sample(sample_bytes, key, ivs[i], crypt, skip,
                                        subsamples=subs_list[i] if i < len(subs_list) else None)
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
            # Try to detect init segment to grab tenc info (pattern, iv size)
            # Parse top boxes to see if moov present with no moof
            s = BytesIO(content)
            has_moov = False
            has_moof = False
            while True:
                pos = s.tell()
                box = _read_box(s)
                if not box:
                    break
                typ, start, header, size, payload = box
                if typ == 'moov':
                    has_moov = True
                elif typ == 'moof':
                    has_moof = True
            default_iv_size = 16
            pattern = (1, 9)
            # If init segment, attempt to read tenc
            if has_moov and not has_moof:
                # Very light tenc parse
                def find_tenc(data: bytes) -> Tuple[int, Tuple[int,int]]:
                    # returns (default_iv_size, (crypt, skip)) when found
                    # walk: moov->trak->mdia->minf->stbl->stsd->encv/enca->sinf->schm/schi->tenc
                    # We'll just search for 'tenc' box anywhere under moov
                    crypt, skip = 1, 9
                    iv_sz = 16
                    tencs = _find_boxes(content, ['tenc'])
                    for _, _, _, tenc_payload in tencs:
                        b = BytesIO(tenc_payload)
                        version = int.from_bytes(b.read(1), 'big')
                        _flags = int.from_bytes(b.read(3), 'big')
                        _isProtected = int.from_bytes(b.read(1), 'big')
                        iv_size = int.from_bytes(b.read(1), 'big')
                        _kid = b.read(16)
                        if version == 1:
                            crypt = int.from_bytes(b.read(1), 'big')
                            skip = int.from_bytes(b.read(1), 'big')
                        if iv_size in (8, 16):
                            iv_sz = iv_size
                        return iv_sz, (max(1, crypt), max(0, skip))
                    return iv_sz, (crypt, skip)
                try:
                    default_iv_size, pattern = find_tenc(content)
                except Exception:
                    pass
                # For init segments, just return as-is
                return Response(content, content_type=content_type)

            decrypted = decrypt_cbcs_fmp4(content, key, default_iv_size=default_iv_size, pattern=pattern)
            return Response(decrypted, content_type=content_type)
        except Exception:
            # Fallback to pass-through on errors (experimental feature)
            return Response(content, content_type=content_type)

    return Response(content, content_type=content_type)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
