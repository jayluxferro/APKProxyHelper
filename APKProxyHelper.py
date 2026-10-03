"""
APKProxyHelper - patch an APK so its traffic can be intercepted by a proxy.

Adds to the target APK, without touching anything else:
  * res/xml/network_security_config.xml  (debug NSC: user CAs + cleartext allowed)
  * a resources.arsc entry so the config is reachable as @xml/network_security_config
  * manifest attributes on <application>:
      android:networkSecurityConfig="@xml/network_security_config"
      android:usesCleartextTraffic="true"
      android:debuggable="true"

Why zip surgery instead of apktool decompile/recompile?
  apktool's decoder gives up on some resources ("Could not decode file,
  replacing by FALSE value" - seen on HDO Box 4.4.6: res/qz.xml, a perfectly
  valid binary animator XML that apktool 2.10 simply fails to parse). The
  FALSE placeholders then fail `aapt2 compile` on rebuild, so the whole
  pipeline dies for apps that would work fine untouched. Patching never
  requires decoding resources: the manifest is edited as binary AXML and the
  new resource is appended to the original resources.arsc in place. Every
  other zip entry is copied byte-for-byte, so apps with undecodable resources
  still build - and keep working, since their arsc is not regenerated.
"""

import os
import shlex
import struct
import subprocess
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# android framework attr resource ids (verified with `aapt2 dump xmltree` on a
# freshly linked test APK against platforms;android-34 - do not "fix" from memory)
ATTR_ID_DEBUGGABLE = 0x0101000F
ATTR_ID_USES_CLEARTEXT = 0x010104EC
ATTR_ID_NETWORK_SECURITY_CONFIG = 0x01010527

# Res_value.dataType codes
VAL_TYPE_REFERENCE = 0x01
VAL_TYPE_STRING = 0x03
VAL_TYPE_BOOLEAN = 0x12

BOOL_TRUE = 0xFFFFFFFF  # convention: any non-zero is true, aapt writes -1

NO_INDEX = 0xFFFFFFFF

NSC_FILE_NAME = "network_security_config.xml"
NSC_RES_NAME = "network_security_config"

# debug NSC: user CAs trusted (mitm proxy CA) + cleartext explicitly allowed.
# cleartextTrafficPermitted is spelled out because relying on the default is
# what bit us during the manual HDO Box bypass.
DEFAULT_NSC = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""

# debug keystore used for re-signing (standard android debug credentials)
DEFAULT_KEYSTORE = os.path.join(str(Path.home()), ".android", "debug.keystore")
DEFAULT_KEY_ALIAS = "androiddebugkey"
DEFAULT_KEY_PASS = "android"


def _run_command(command):
    print("    $ " + " ".join(shlex.quote(str(c)) for c in command))
    # No shell=True: argument lists avoid quoting pitfalls, and the
    # readline-until-EOF + wait() pattern below cannot busy-loop (an earlier
    # revision compared bytes b"" against "" - never equal on py3 - and spun
    # at 100% CPU once the child closed its stdout).
    process = subprocess.Popen(
        [str(c) for c in command],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    for raw_line in iter(process.stdout.readline, b""):
        print(raw_line.decode("utf-8", "replace").rstrip())
    process.stdout.close()
    return process.wait()


# ---------------------------------------------------------------------------
# Binary string pool (ResStringPool) - used by both AXML and resources.arsc.
# Handles UTF-8 and UTF-16 pools. Style spans (styled strings) are preserved
# verbatim: we only ever APPEND strings, so original indices (which spans
# refer to) stay valid.
# ---------------------------------------------------------------------------


class StringPool:
    def __init__(self):
        self.utf8 = True
        self.strings = []
        self._styles = b""  # raw span block incl. sentinel, kept verbatim
        self._style_count = 0

    @staticmethod
    def parse(data, off):
        pool = StringPool()
        chunk_type, header_size = struct.unpack_from("<HH", data, off)
        if chunk_type != 0x0001:
            raise ValueError("expected string pool chunk, got 0x%04x" % chunk_type)
        (chunk_size,) = struct.unpack_from("<I", data, off + 4)
        pool.size = chunk_size
        (str_count, style_count, flags, strings_start, styles_start) = struct.unpack_from(
            "<IIIII", data, off + 8
        )
        pool.utf8 = bool(flags & 0x100)
        pool._style_count = style_count
        offsets = struct.unpack_from("<%dI" % str_count, data, off + 28)
        base = off + strings_start
        for o in offsets:
            p = base + o
            if pool.utf8:
                _, p = StringPool._decode_len8(data, p)
                u8len, p = StringPool._decode_len8(data, p)
                pool.strings.append(data[p : p + u8len].decode("utf-8", "replace"))
            else:
                u16len, p = StringPool._decode_len16(data, p)
                pool.strings.append(
                    data[p : p + 2 * u16len].decode("utf-16-le", "replace")
                )
        if style_count > 0:
            pool._styles = bytes(data[off + styles_start : off + chunk_size])
        return pool

    @staticmethod
    def _decode_len8(data, p):
        l = data[p]
        p += 1
        if l & 0x80:
            l = ((l & 0x7F) << 8) | data[p]
            p += 1
        return l, p

    @staticmethod
    def _decode_len16(data, p):
        l = struct.unpack_from("<H", data, p)[0]
        p += 2
        if l & 0x8000:
            l = ((l & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
            p += 2
        return l, p

    @staticmethod
    def _encode_len8(v):
        if v < 0x80:
            return bytes([v])
        return bytes([0x80 | (v >> 8), v & 0xFF])

    @staticmethod
    def _encode_len16(v):
        if v < 0x8000:
            return struct.pack("<H", v)
        return struct.pack("<HH", 0x8000 | (v >> 16), v & 0xFFFF)

    def index_of(self, s):
        try:
            return self.strings.index(s)
        except ValueError:
            return -1

    def append(self, s):
        """Append string, returning its index (dedup: reuse if present)."""
        idx = self.index_of(s)
        if idx >= 0:
            return idx
        self.strings.append(s)
        return len(self.strings) - 1

    def _encode_string(self, s):
        # aapt measures length in UTF-16 code units, not code points
        u16len = len(s.encode("utf-16-le")) // 2
        if self.utf8:
            raw = s.encode("utf-8")
            return self._encode_len8(u16len) + self._encode_len8(len(raw)) + raw + b"\x00"
        return self._encode_len16(u16len) + s.encode("utf-16-le") + b"\x00\x00"

    def serialize(self):
        # The SORTED flag (0x1) is dropped on rewrite: appended strings would
        # break sort order, and unsorted pools are always legal (lookups fall
        # back to a linear scan).
        flags = 0x100 if self.utf8 else 0x0
        enc = [self._encode_string(s) for s in self.strings]
        count = len(self.strings)
        strings_start = 28 + 4 * count
        strings_start += (-strings_start) % 4
        if self._style_count > 0:
            styles_start = strings_start + sum(len(e) for e in enc)
            styles_start += (-styles_start) % 4  # spans need 4-byte alignment
            chunk_size = styles_start + len(self._styles)
        else:
            styles_start = 0
            chunk_size = strings_start + sum(len(e) for e in enc)
        chunk_size += (-chunk_size) % 4
        out = bytearray(
            struct.pack(
                "<HHIIIIII",
                0x0001,
                28,
                chunk_size,
                count,
                self._style_count,
                flags,
                strings_start,
                styles_start,
            )
        )
        cur = 0
        for e in enc:
            out += struct.pack("<I", cur)
            cur += len(e)
        out += b"\x00" * (strings_start - len(out))
        for e in enc:
            out += e
        if self._style_count > 0:
            out += b"\x00" * (styles_start - len(out))
            out += self._styles
        out += b"\x00" * (chunk_size - len(out))
        return bytes(out)


# ---------------------------------------------------------------------------
# Binary XML (AXML) editing: parse the manifest, splice attributes into
# <application>, re-serialize with a fresh string pool / resource map.
# Original string indices are preserved (pool rebuilt in order, appends only),
# so every untouched node and every style span keeps working.
# ---------------------------------------------------------------------------


class AxmlNode:
    START_NS = 0x0100
    END_NS = 0x0101
    START_ELEMENT = 0x0102
    END_ELEMENT = 0x0103
    CDATA = 0x0104


class Attribute:
    def __init__(self, ns, name, raw_value, data_type, data):
        self.ns = ns
        self.name = name  # string pool index
        self.raw_value = raw_value  # string pool index or NO_INDEX
        self.data_type = data_type
        self.data = data


class AxmlDocument:
    def __init__(self, data):
        self.pool = None
        self.res_ids = []  # resource-map entries indexed by string index
        self.nodes = []
        self._parse(data)

    def _parse(self, data):
        xml_type, xml_hdr, xml_size = struct.unpack_from("<HHI", data, 0)
        if xml_type != 0x0003:
            raise ValueError("not an AXML document (type=0x%04x)" % xml_type)
        off = xml_hdr
        while off < xml_size:
            chunk_type, chunk_hdr = struct.unpack_from("<HH", data, off)
            (chunk_size,) = struct.unpack_from("<I", data, off + 4)
            line = struct.unpack_from("<I", data, off + 8)[0]
            comment = struct.unpack_from("<I", data, off + 12)[0]
            if chunk_type == 0x0001:
                self.pool = StringPool.parse(data, off)
            elif chunk_type == 0x0180:
                n = (chunk_size - chunk_hdr) // 4
                self.res_ids = list(struct.unpack_from("<%dI" % n, data, off + chunk_hdr))
            elif chunk_type in (AxmlNode.START_NS, AxmlNode.END_NS):
                prefix, uri = struct.unpack_from("<II", data, off + 16)
                self.nodes.append(
                    dict(kind=chunk_type, line=line, comment=comment, prefix=prefix, uri=uri)
                )
            elif chunk_type == AxmlNode.START_ELEMENT:
                ns, name = struct.unpack_from("<II", data, off + 16)
                attr_start, attr_size, attr_count, id_idx, class_idx, style_idx = struct.unpack_from(
                    "<HHHHHH", data, off + 24
                )
                attrs = []
                abase = off + 16 + attr_start
                for i in range(attr_count):
                    a = abase + i * attr_size
                    ans, aname, raw = struct.unpack_from("<III", data, a)
                    vsize, vres0, vtype, vdata = struct.unpack_from("<HBBI", data, a + 12)
                    attrs.append(Attribute(ans, aname, raw, vtype, vdata))
                self.nodes.append(
                    dict(
                        kind=chunk_type,
                        line=line,
                        comment=comment,
                        ns=ns,
                        name=name,
                        attr_start=attr_start,
                        attr_size=attr_size,
                        id_idx=id_idx,
                        class_idx=class_idx,
                        style_idx=style_idx,
                        attrs=attrs,
                    )
                )
            elif chunk_type == AxmlNode.END_ELEMENT:
                ns, name = struct.unpack_from("<II", data, off + 16)
                self.nodes.append(dict(kind=chunk_type, line=line, comment=comment, ns=ns, name=name))
            elif chunk_type == AxmlNode.CDATA:
                (cdata,) = struct.unpack_from("<I", data, off + 16)
                self.nodes.append(dict(kind=chunk_type, line=line, comment=comment, data=cdata))
            else:
                # unknown chunk kind: keep bytes verbatim
                self.nodes.append(dict(kind=chunk_type, raw=bytes(data[off : off + chunk_size])))
            off += chunk_size

    # -- helpers -------------------------------------------------------------

    def elements(self, name):
        for n in self.nodes:
            if n["kind"] == AxmlNode.START_ELEMENT and self.pool.strings[n["name"]] == name:
                yield n

    def android_ns_index(self):
        idx = self.pool.index_of(ANDROID_NS)
        if idx >= 0:
            return idx
        return self.pool.append(ANDROID_NS)

    def str_index(self, s):
        return self.pool.append(s)

    def find_android_attr(self, node, attr_name):
        for a in node["attrs"]:
            if a.ns != NO_INDEX and self.pool.strings[a.name] == attr_name:
                return a
        return None

    ATTR_IDS = {
        "debuggable": ATTR_ID_DEBUGGABLE,
        "usesCleartextTraffic": ATTR_ID_USES_CLEARTEXT,
        "networkSecurityConfig": ATTR_ID_NETWORK_SECURITY_CONFIG,
    }

    def set_or_add_attr(self, node, attr_name, data_type, data, raw):
        ns = self.android_ns_index()
        name_idx = self.str_index(attr_name)
        raw_idx = self.str_index(raw) if raw is not None else NO_INDEX
        a = self.find_android_attr(node, attr_name)
        if a is None:
            node["attrs"].append(Attribute(ns, name_idx, raw_idx, data_type, data))
        else:
            a.ns = ns
            a.data_type = data_type
            a.data = data
            a.raw_value = raw_idx
        # PackageParser matches attributes by RESOURCE ID via the resource-map
        # chunk, so the map must carry the framework attr id for every attr
        # name we touch. Extend it to cover the whole string pool (a map
        # longer than the original is always safe; shorter would not be).
        while len(self.res_ids) < len(self.pool.strings):
            self.res_ids.append(0)
        self.res_ids[name_idx] = self.ATTR_IDS[attr_name]
        # AssetManager2::RetrieveAttributes (AttributeResolution.cpp) - the
        # code behind every obtainAttributes() on a manifest - does an
        # ascending MERGE-WALK over the requested styleable array and the
        # element's attributes, assuming both are sorted by resource id
        # (which aapt2 guarantees for files it emits). An out-of-order
        # attribute is skipped SILENTLY: aapt2 dump xmltree still resolves
        # it, but debuggable/usesCleartextTraffic simply do not apply at
        # runtime. Re-sort into canonical order (attrs without a resource
        # id - e.g. tools:/package - go last, relative order preserved).
        node["attrs"].sort(key=self._attr_sort_key)

    def _attr_sort_key(self, a):
        resid = self.res_ids[a.name] if a.name < len(self.res_ids) else 0
        return (1 if resid == 0 else 0, resid)

    # -- serialization -------------------------------------------------------

    def serialize(self):
        out = bytearray()
        out += struct.pack("<HHI", 0x0003, 8, 0)  # size patched at the end
        out += self.pool.serialize()
        if self.res_ids:  # synthetic docs (compiled NSC) carry no resource map
            out += self._serialize_res_map()
        for n in self.nodes:
            out += self._serialize_node(n)
        struct.pack_into("<I", out, 4, len(out))
        return bytes(out)

    def _serialize_res_map(self):
        data = b"".join(struct.pack("<I", v) for v in self.res_ids)
        return struct.pack("<HHI", 0x0180, 8, 8 + len(data)) + data

    def _node_header(self, n, body_len):
        # ResXMLTree_node: {type, headerSize=16, size, lineNumber, comment}
        size = 16 + body_len
        return struct.pack(
            "<HHIII", n["kind"], 16, size, n.get("line", 0), n.get("comment", NO_INDEX)
        )

    def _serialize_node(self, n):
        k = n["kind"]
        if "raw" in n:
            return n["raw"]
        if k in (AxmlNode.START_NS, AxmlNode.END_NS):
            return self._node_header(n, 8) + struct.pack("<II", n["prefix"], n["uri"])
        if k == AxmlNode.CDATA:
            return self._node_header(n, 4) + struct.pack("<I", n["data"])
        if k == AxmlNode.END_ELEMENT:
            return self._node_header(n, 8) + struct.pack("<II", n["ns"], n["name"])
        if k == AxmlNode.START_ELEMENT:
            # attrExt: ns, name, attributeStart(0x14), attributeSize(0x14),
            # attributeCount, idIndex, classIndex, styleIndex
            attr_ext = struct.pack(
                "<IIHHHHHH",
                n["ns"],
                n["name"],
                0x14,
                0x14,
                len(n["attrs"]),
                n["id_idx"],
                n["class_idx"],
                n["style_idx"],
            )
            attrs = b"".join(self._serialize_attr(a) for a in n["attrs"])
            return self._node_header(n, len(attr_ext) + len(attrs)) + attr_ext + attrs
        raise ValueError("unserializable node kind 0x%04x" % k)

    @staticmethod
    def _serialize_attr(a):
        # ResXMLTree_attribute + typed value = 20 bytes:
        # ns(I) name(I) rawValue(I) | typedValue: size(H) res0(B) dataType(B) data(I)
        return struct.pack("<IIIHBBI", a.ns, a.name, a.raw_value, 8, 0, a.data_type, a.data)


def compile_xml_to_axml(text):
    """Compile a simple text XML resource to binary AXML.

    The framework reads res/xml resources through ResXMLTree, which only
    accepts COMPILED binary XML: the text payload this tool originally
    embedded decodes fine with `aapt2 dump` but fails at bind time with
    "Failed to parse XML configuration from network_security_config_aph"
    (the app is killed before Application.onCreate). aapt2 does this
    compilation in a normal build; reimplemented here so the tool stays
    self-contained. Scope is exactly the NSC schema: nested elements with
    namespace-free string-valued attributes, no text content, no resource
    references - anything else raises rather than emitting broken AXML.
    """
    root = ET.fromstring(text)
    doc = AxmlDocument.__new__(AxmlDocument)
    doc.pool = StringPool()  # utf-8 pool, like aapt2 writes for xml resources
    doc.res_ids = []  # no resource map: the NSC parser reads attrs by name
    doc.nodes = []

    def sid(s):
        i = doc.pool.index_of(s)
        return i if i >= 0 else doc.pool.append(s)

    def walk(elem):
        name_idx = sid(elem.tag)
        attrs = []
        for k, v in elem.attrib.items():
            ki, vi = sid(k), sid(v)
            # string attr: rawValue and typed value both point into the pool
            attrs.append(Attribute(NO_INDEX, ki, vi, VAL_TYPE_STRING, vi))
        doc.nodes.append(
            dict(
                kind=AxmlNode.START_ELEMENT,
                line=1,
                comment=NO_INDEX,
                ns=NO_INDEX,
                name=name_idx,
                id_idx=0,
                class_idx=0,
                style_idx=0,
                attrs=attrs,
            )
        )
        if elem.text and elem.text.strip():
            raise ValueError("text content not supported in %s" % elem.tag)
        for child in elem:
            walk(child)
            if child.tail and child.tail.strip():
                raise ValueError("text content not supported in %s" % child.tag)
        doc.nodes.append(
            dict(
                kind=AxmlNode.END_ELEMENT,
                line=1,
                comment=NO_INDEX,
                ns=NO_INDEX,
                name=name_idx,
            )
        )

    walk(root)
    return doc.serialize()


# ---------------------------------------------------------------------------
# resources.arsc editing: append one file-backed entry of type "xml".
# The original arsc is never decoded/regenerated - only grown at chunk
# boundaries - so obfuscated/unusual resources survive untouched.
# ---------------------------------------------------------------------------


class ArscPackage:
    def __init__(self, data, off):
        self.off = off
        (self.chunk_type, self.header_size, self.size, self.id) = struct.unpack_from(
            "<HHII", data, off
        )
        self.raw_name = bytes(data[off + 12 : off + 268])  # 128 UTF-16 units, verbatim
        (
            self.type_strings_off,
            self.last_public_type,
            self.key_strings_off,
            self.last_public_key,
            self.type_id_offset,
        ) = struct.unpack_from("<IIIII", data, off + 268)
        self.type_pool = StringPool.parse(data, off + self.type_strings_off)
        self.key_pool = StringPool.parse(data, off + self.key_strings_off)
        # type spec/type chunks follow the key strings pool (the two string
        # pools sit between the fixed header and them); keep them in original
        # order. Parsed dicts carry enough state to rebuild a modified chunk,
        # raw bytes are copied verbatim otherwise.
        self.chunks = []
        c = off + self.key_strings_off + self.key_pool.size
        end = off + self.size
        while c < end:
            ctype, chdr = struct.unpack_from("<HH", data, c)
            (csize,) = struct.unpack_from("<I", data, c + 4)
            entry = dict(kind=ctype, raw=bytes(data[c : c + csize]))
            if ctype in (0x0201, 0x0204):
                flags = struct.unpack_from("<H", data, c + 10)[0]
                entry.update(
                    dict(
                        type_id=data[c + 8],
                        flags=flags,
                        entry_count=struct.unpack_from("<I", data, c + 12)[0],
                        entries_start=struct.unpack_from("<I", data, c + 16)[0],
                        config_size=struct.unpack_from("<I", data, c + 20)[0],
                        header_size=chdr,
                        is_sparse=(ctype == 0x0204 or bool(flags & 0x01)),
                        is_off16=bool(flags & 0x02),
                    )
                )
            elif ctype == 0x0202:
                entry.update(dict(type_id=data[c + 8]))
            self.chunks.append(entry)
            c += csize

    def type_index(self, type_name):
        try:
            return self.type_pool.strings.index(type_name) + 1
        except ValueError:
            return -1

    def type_chunks(self, type_id):
        return [
            c
            for c in self.chunks
            if c.get("type_id") == type_id and c["kind"] in (0x0201, 0x0204)
        ]

    def type_spec(self, type_id):
        for c in self.chunks:
            if c["kind"] == 0x0202 and c.get("type_id") == type_id:
                return c
        return None

    @staticmethod
    def is_default_config(chunk):
        # default config = every qualifier byte zero. The first 4 bytes of the
        # region are ResTable_config.size itself (always non-zero), so compare
        # only the qualifier payload after it.
        region = chunk["raw"][20 : 20 + chunk["config_size"]]
        return region[4:] == b"\x00" * (len(region) - 4)

    def _iter_entries(self, chunk):
        """Yield (entry_index, byte_offset_into_entries_data) for present entries."""
        raw = chunk["raw"]
        hdr = chunk["header_size"]
        n = chunk["entry_count"]
        if n <= 0 or len(raw) <= hdr:
            return
        if chunk["is_sparse"]:
            count = (len(raw) - hdr) // 4
            vals = struct.unpack_from("<%dH" % (2 * count), raw, hdr)
            for i in range(count):
                yield vals[2 * i], vals[2 * i + 1] * 4  # sparse offsets are /4
        elif chunk["is_off16"]:
            offs = struct.unpack_from("<%dH" % (2 * n), raw, hdr)
            for i in range(n):
                off = offs[2 * i] | (offs[2 * i + 1] << 16)
                if off != NO_INDEX:
                    yield i, off * 4
        else:
            offs = struct.unpack_from("<%dI" % n, raw, hdr)
            for i in range(n):
                if offs[i] != NO_INDEX:
                    yield i, offs[i]

    @staticmethod
    def _entry_total_len(raw, p):
        """Byte length of the entry at raw[p] (simple or complex/bag)."""
        esize, eflags = struct.unpack_from("<HH", raw, p)
        if eflags & 0x01:  # COMPLEX: maps follow (20 bytes each)
            count = struct.unpack_from("<I", raw, p + 12)[0]
            return esize + count * 20
        return esize + 8  # + Res_value

    def _entry_value(self, chunk, entry_index):
        """(dataType, data) of a simple entry, or None for bags."""
        raw = chunk["raw"]
        es = chunk["entries_start"]
        for i, off in self._iter_entries(chunk):
            if i == entry_index:
                p = es + off
                eflags = struct.unpack_from("<H", raw, p + 2)[0]
                if eflags & 0x01:
                    return None
                esize = struct.unpack_from("<H", raw, p)[0]
                vsize, vres0, vtype, vdata = struct.unpack_from("<HBBI", raw, p + esize)
                return (vtype, vdata)
        return None

    def entry_file_paths(self, type_id, global_pool):
        """All file-backed entries of a type: {resource_id: file_path}."""
        out = {}
        for chunk in self.type_chunks(type_id):
            for i, _ in self._iter_entries(chunk):
                value = self._entry_value(chunk, i)
                if value and value[0] == VAL_TYPE_STRING:
                    rid = (self.id << 24) | (type_id << 16) | i
                    out[rid] = global_pool.strings[value[1]]
        return out

    def append_file_entry(self, type_id, key_name, file_path, global_pool):
        """Add one file-backed resource to this package; return the resource id.

        The entry goes into the type's DEFAULT-config chunk (created if
        absent). The new entry index is one beyond the highest index used by
        ANY config chunk of the type, so an exact-id lookup can never resolve
        to another config chunk that also happens to contain that index.
        """
        global_idx = global_pool.append(file_path)
        key_idx = self.key_pool.append(key_name)

        chunks = self.type_chunks(type_id)
        entry_idx = max([c["entry_count"] for c in chunks] + [0])
        host = None
        for c in chunks:
            if self.is_default_config(c):
                host = c
                break
        if host is None:
            host = dict(
                kind=0x0201,
                type_id=type_id,
                flags=0,
                entry_count=0,
                entries_start=0,
                config_size=64,
                header_size=84,
                is_sparse=False,
                is_off16=False,
                raw=b"",  # empty config region -> written as default config
            )
            self.chunks.append(host)
            if self.type_spec(type_id) is None:
                # TYPE_SPEC: {hdr(8), id, res0, flags, entryCount} + flags array
                n = entry_idx + 1
                self.chunks.append(
                    dict(
                        kind=0x0202,
                        type_id=type_id,
                        raw=struct.pack("<HHIBBHI", 0x0202, 16, 16 + 4 * n, type_id, 0, 0, n)
                        + b"\x00" * (4 * n),
                    )
                )

        entry = struct.pack("<HHI", 8, 0, key_idx) + struct.pack(
            "<HBBI", 8, 0, VAL_TYPE_STRING, global_idx
        )
        new_raw, new_count = self._rebuild_type_chunk(host, entry_idx, entry)
        host["raw"] = new_raw
        host["entry_count"] = new_count

        spec = self.type_spec(type_id)
        if spec is not None and len(spec["raw"]) >= 16:
            n = struct.unpack_from("<I", spec["raw"], 12)[0]
            if n < host["entry_count"]:
                # grow the entry-flag array to match the new entry count;
                # rebuild the whole chunk so the size field stays truthful
                # (a stale size makes aapt2/framework walk chunks misaligned)
                spec["raw"] = (
                    struct.pack(
                        "<HHIBBHI",
                        0x0202,
                        16,
                        16 + 4 * host["entry_count"],
                        type_id,
                        0,
                        0,
                        host["entry_count"],
                    )
                    + spec["raw"][16:]
                    + b"\x00" * (4 * (host["entry_count"] - n))
                )

        self.last_public_type = max(self.last_public_type, type_id)
        self.last_public_key = max(self.last_public_key, key_idx)
        return (self.id << 24) | (type_id << 16) | entry_idx

    def _rebuild_type_chunk(self, chunk, entry_idx, entry_bytes):
        """Rebuild a type chunk with one more entry.

        Sparse (0x0204) and OFFSET16 chunks are converted to the plain uint32
        offset layout - always valid and the simplest shape to extend. Existing
        entries are copied verbatim; gaps stay as NO_INDEX holes (dense chunks
        with holes are exactly what aapt emits for sparse key spaces).
        """
        raw = chunk["raw"]
        n = chunk["entry_count"]
        config = raw[20 : 20 + chunk["config_size"]]
        hdr_size = 20 + len(config)

        entries = {}
        for i, off in self._iter_entries(chunk):
            p = chunk["entries_start"] + off
            entries[i] = raw[p : p + self._entry_total_len(raw, p)]

        new_count = max(n, entry_idx + 1)
        offsets = []
        data = bytearray()
        for i in range(new_count):
            if i in entries:
                offsets.append(len(data))
                data += entries[i]
            elif i == entry_idx:
                offsets.append(len(data))
                data += entry_bytes
            else:
                offsets.append(NO_INDEX)
        entries_start = hdr_size + 4 * new_count
        entries_start += (-entries_start) % 4
        chunk_size = entries_start + len(data)
        chunk_size += (-chunk_size) % 4
        out = bytearray(
            struct.pack(
                "<HHIBBHII",
                0x0201,
                hdr_size,
                chunk_size,
                chunk["type_id"],
                0,
                0,  # flags: not sparse, not offset16
                new_count,
                entries_start,
            )
        )
        out += config
        out += b"".join(struct.pack("<I", o) for o in offsets)
        out += b"\x00" * (entries_start - len(out))
        out += data
        out += b"\x00" * (chunk_size - len(out))
        return bytes(out), new_count

    def serialize(self):
        tp = self.type_pool.serialize()
        kp = self.key_pool.serialize()
        body = tp + kp + b"".join(c["raw"] for c in self.chunks)
        header = struct.pack("<HHII", 0x0200, self.header_size, self.header_size + len(body), self.id)
        header += self.raw_name
        header += struct.pack(
            "<IIIII",
            self.header_size,  # typeStrings starts right after the fixed header
            self.last_public_type,
            self.header_size + len(tp),  # keyStrings after the type pool
            self.last_public_key,
            self.type_id_offset,
        )
        return header + body


class ArscTable:
    def __init__(self, data):
        self.data = bytes(data)
        (self.chunk_type, self.header_size, self.size, self.package_count) = struct.unpack_from(
            "<HHII", self.data, 0
        )
        if self.chunk_type != 0x0002:
            raise ValueError("not a resources.arsc table (type=0x%04x)" % self.chunk_type)
        self.global_pool = StringPool.parse(self.data, self.header_size)
        self.packages = []
        off = self.header_size + struct.unpack_from("<I", self.data, self.header_size + 4)[0]
        for _ in range(self.package_count):
            pkg = ArscPackage(self.data, off)
            self.packages.append(pkg)
            off += pkg.size

    def app_package(self):
        # the manifest resolves refs against the app's own package (0x7f);
        # fall back to the first package for shared-library style tables
        for p in self.packages:
            if p.id == 0x7F:
                return p
        return self.packages[0] if self.packages else None

    def serialize(self):
        body = self.global_pool.serialize() + b"".join(p.serialize() for p in self.packages)
        header = struct.pack(
            "<HHII", 0x0002, self.header_size, self.header_size + len(body), self.package_count
        )
        return header + body


# ---------------------------------------------------------------------------


def find_build_tools():
    """Locate zipalign/apksigner under $ANDROID_HOME or the common macOS path."""
    home = os.environ.get("ANDROID_HOME") or os.path.expanduser("~/androidSdk")
    bt = os.path.join(home, "build-tools")
    versions = sorted(os.listdir(bt), reverse=True) if os.path.isdir(bt) else []
    # prefer 34.0.0 (matches the audit bench toolchain), else newest
    if "34.0.0" in versions:
        versions = ["34.0.0"] + [v for v in versions if v != "34.0.0"]
    for v in versions:
        if os.path.isfile(os.path.join(bt, v, "zipalign")) and os.path.isfile(
            os.path.join(bt, v, "apksigner")
        ):
            return os.path.join(bt, v)
    raise FileNotFoundError("zipalign/apksigner not found under %s - set ANDROID_HOME" % bt)


class APKProxyHelper:
    def __init__(self, apk_path, out_path=None, keystore=None):
        self.apk = os.path.normpath(os.path.expanduser(apk_path))
        self.file_name = os.path.splitext(os.path.basename(self.apk))[0]
        default_out = os.path.join(
            os.path.dirname(self.apk), "{}_proxy.apk".format(self.file_name)
        )
        self.patched_apk = (
            os.path.normpath(os.path.expanduser(out_path)) if out_path else default_out
        )
        self.keystore = (
            os.path.normpath(os.path.expanduser(keystore)) if keystore else DEFAULT_KEYSTORE
        )
        self.build_tools = None

    # Public methods
    def patch_apk(self):
        if not os.path.isfile(self.apk):
            raise FileNotFoundError(self.apk)
        self._read_apk()
        resid = self._add_network_resource()
        self._patch_manifest(resid)
        self._write_apk()
        self._align_apk()
        self._resign_apk()
        print("[+] Patched APK written to {}".format(self.patched_apk))

    # Private methods
    def _read_apk(self):
        print("[*] Reading {}".format(self.apk))
        self.zin = zipfile.ZipFile(self.apk, "r")
        self.names = self.zin.namelist()
        if "AndroidManifest.xml" not in self.names or "resources.arsc" not in self.names:
            raise ValueError("not an APK: missing AndroidManifest.xml/resources.arsc")

    def _add_network_resource(self):
        """Ensure an @xml/network_security_config resource exists in the arsc.

        Reuses an existing xml-type file entry named network_security_config.xml
        when present (idempotent re-runs, or apps that already ship an NSC -
        the file content is replaced with the debug config either way);
        otherwise appends a fresh entry to the original arsc.
        """
        print("[*] Patching resources.arsc")
        arsc = ArscTable(self.zin.read("resources.arsc"))
        self.arsc = arsc
        pkg = arsc.app_package()
        if pkg is None:
            raise ValueError("resources.arsc contains no resource packages")

        resid = None
        type_id = pkg.type_index("xml")
        if type_id > 0:
            for rid, path in pkg.entry_file_paths(type_id, arsc.global_pool).items():
                if os.path.basename(path) == NSC_FILE_NAME:
                    resid = rid
                    self.nsc_zip_path = path
                    break
        if resid is not None:
            print("    reusing existing resource 0x%08x (%s)" % (resid, self.nsc_zip_path))
        else:
            key = NSC_RES_NAME
            while key in pkg.key_pool.strings:
                key += "_aph"
            path = "res/xml/%s.xml" % key
            while path in self.names:
                key += "_aph"
                path = "res/xml/%s.xml" % key
            if type_id < 0:
                # register the "xml" type name; its type index = pool pos + 1
                type_id = pkg.type_pool.append("xml") + 1
            resid = pkg.append_file_entry(type_id, key, path, arsc.global_pool)
            self.nsc_zip_path = path
            print("    added resource 0x%08x -> %s" % (resid, path))
        self.patched_arsc = arsc.serialize()
        # compiled once here so _write_apk can embed it in either branch
        self.nsc_payload = compile_xml_to_axml(DEFAULT_NSC)
        return resid

    def _patch_manifest(self, resid):
        print("[*] Patching AndroidManifest.xml")
        doc = AxmlDocument(self.zin.read("AndroidManifest.xml"))
        apps = list(doc.elements("application"))
        if not apps:
            raise ValueError("manifest has no <application> element")
        app = apps[0]
        raw_ref = "@xml/" + os.path.splitext(os.path.basename(self.nsc_zip_path))[0]
        # All three attributes are required for reliable interception:
        #  - networkSecurityConfig -> our debug NSC (trust user CAs for TLS)
        #  - usesCleartextTraffic  -> allows http://; okhttp consults this
        #    platform flag, and the NSC alone did NOT suffice in our manual
        #    HDO Box bypass
        #  - debuggable            -> activates the NSC <debug-overrides>
        doc.set_or_add_attr(app, "networkSecurityConfig", VAL_TYPE_REFERENCE, resid, raw_ref)
        doc.set_or_add_attr(app, "usesCleartextTraffic", VAL_TYPE_BOOLEAN, BOOL_TRUE, "true")
        doc.set_or_add_attr(app, "debuggable", VAL_TYPE_BOOLEAN, BOOL_TRUE, "true")
        self.patched_manifest = doc.serialize()

    def _write_apk(self):
        """Rezip: every original entry byte-for-byte (same compression), with
        the three patched entries replaced and stale signatures dropped."""
        print("[*] Writing {}".format(self.patched_apk))
        sig_suffixes = (".SF", ".RSA", ".DSA", ".EC")
        with zipfile.ZipFile(self.patched_apk, "w") as zout:
            for info in self.zin.infolist():
                name = info.filename
                if name.startswith("META-INF/") and (
                    name == "META-INF/MANIFEST.MF" or name.endswith(sig_suffixes)
                ):
                    continue  # stale signature artifacts
                if name == "AndroidManifest.xml":
                    payload, method = self.patched_manifest, zipfile.ZIP_DEFLATED
                elif name == "resources.arsc":
                    # API 30+ requires resources.arsc stored uncompressed
                    payload, method = self.patched_arsc, zipfile.ZIP_STORED
                elif name == self.nsc_zip_path:
                    payload, method = self.nsc_payload, zipfile.ZIP_DEFLATED
                else:
                    payload, method = self.zin.read(name), info.compress_type
                zi = zipfile.ZipInfo(name, date_time=info.date_time)
                zi.compress_type = method
                zi.external_attr = info.external_attr
                zout.writestr(zi, payload)
            if self.nsc_zip_path not in self.names:
                zi = zipfile.ZipInfo(self.nsc_zip_path, date_time=(2024, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(zi, self.nsc_payload)
        self.zin.close()

    def _align_apk(self):
        self.build_tools = find_build_tools()
        print("[*] zipalign ({})".format(self.build_tools))
        aligned = self.patched_apk + ".aligned"
        rc = _run_command(
            [
                os.path.join(self.build_tools, "zipalign"),
                "-f",
                "-p",
                "4",
                self.patched_apk,
                aligned,
            ]
        )
        if rc != 0:
            raise RuntimeError("zipalign failed")
        os.replace(aligned, self.patched_apk)

    def _resign_apk(self):
        print("[*] Re-signing with debug keystore {}".format(self.keystore))
        rc = _run_command(
            [
                os.path.join(self.build_tools, "apksigner"),
                "sign",
                "--ks",
                self.keystore,
                "--ks-key-alias",
                DEFAULT_KEY_ALIAS,
                "--ks-pass",
                "pass:" + DEFAULT_KEY_PASS,
                "--key-pass",
                "pass:" + DEFAULT_KEY_PASS,
                self.patched_apk,
            ]
        )
        if rc != 0:
            raise RuntimeError("apksigner failed")
        rc = _run_command(
            [os.path.join(self.build_tools, "apksigner"), "verify", self.patched_apk]
        )
        if rc != 0:
            raise RuntimeError("apksigner verify failed")
