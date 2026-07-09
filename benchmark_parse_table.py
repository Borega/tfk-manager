import timeit
import re
from html import unescape as html_unescape

# Function from fetch_webfilter_embedded.py (unoptimized)
def _parse_address_table_unoptimized(html: str, table_id: str, row_class: str) -> list[dict]:
    entries = []
    table_match = re.search(
        rf'<table[^>]*id=["\']{re.escape(table_id)}["\'][^>]*>(.*?)</table>',
        html,
        re.DOTALL | re.IGNORECASE,
    )
    if not table_match:
        return entries

    tbody_match = re.search(r"<tbody>(.*?)</tbody>", table_match.group(1), re.DOTALL | re.IGNORECASE)
    if not tbody_match:
        return entries

    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", tbody_match.group(1), re.DOTALL | re.IGNORECASE)
    for row in rows:
        id_match = re.search(
            rf'class=["\'][^"\']*{re.escape(row_class)}[^"\']*["\'][^>]*value=["\']([^"\']+)["\']',
            row,
            re.IGNORECASE,
        )
        if not id_match:
            id_match = re.search(
                rf'value=["\']([^"\']+)["\'][^>]*class=["\'][^"\']*{re.escape(row_class)}[^"\']*["\']',
                row,
                re.IGNORECASE,
            )
        name_match = re.search(
            r'<td[^>]*class=["\'][^"\']*col_name[^"\']*["\'][^>]*>(.*?)</td>',
            row,
            re.DOTALL | re.IGNORECASE,
        )
        if not id_match or not name_match:
            continue

        entry_id = html_unescape(id_match.group(1)).strip()
        name_raw = re.sub(r"<[^>]+>", "", name_match.group(1))
        name = html_unescape(name_raw).strip()
        if not entry_id:
            continue
        entries.append({"id": entry_id, "name": name})

    return entries


def _parse_address_table_optimized(html: str, table_id: str, row_class: str) -> list[dict]:
    entries = []
    table_match = re.search(
        rf'<table[^>]*id=["\']{re.escape(table_id)}["\'][^>]*>(.*?)</table>',
        html,
        re.DOTALL | re.IGNORECASE,
    )
    if not table_match:
        return entries

    tbody_match = re.search(r"<tbody>(.*?)</tbody>", table_match.group(1), re.DOTALL | re.IGNORECASE)
    if not tbody_match:
        return entries

    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", tbody_match.group(1), re.DOTALL | re.IGNORECASE)

    id_pattern1 = re.compile(rf'class=["\'][^"\']*{re.escape(row_class)}[^"\']*["\'][^>]*value=["\']([^"\']+)["\']', re.IGNORECASE)
    id_pattern2 = re.compile(rf'value=["\']([^"\']+)["\'][^>]*class=["\'][^"\']*{re.escape(row_class)}[^"\']*["\']', re.IGNORECASE)
    name_pattern = re.compile(r'<td[^>]*class=["\'][^"\']*col_name[^"\']*["\'][^>]*>(.*?)</td>', re.DOTALL | re.IGNORECASE)
    strip_tags_pattern = re.compile(r"<[^>]+>")

    for row in rows:
        id_match = id_pattern1.search(row)
        if not id_match:
            id_match = id_pattern2.search(row)
        name_match = name_pattern.search(row)
        if not id_match or not name_match:
            continue

        entry_id = html_unescape(id_match.group(1)).strip()
        name_raw = strip_tags_pattern.sub("", name_match.group(1))
        name = html_unescape(name_raw).strip()
        if not entry_id:
            continue
        entries.append({"id": entry_id, "name": name})

    return entries

# Generate dummy HTML data
table_id = "table_wl_table"
row_class = "selectRow_whitelist"

html_parts = [f'<table id="{table_id}"><tbody>']
for i in range(1000):
    html_parts.append(f'<tr><td class="col_name">name{i}</td><td><input class="{row_class}" value="{i}"></td></tr>')
html_parts.append('</tbody></table>')
html_data = "".join(html_parts)

print("Running baseline...")
baseline_time = timeit.timeit(lambda: _parse_address_table_unoptimized(html_data, table_id, row_class), number=10)
print(f"Baseline (10 runs): {baseline_time:.4f}s")

print("Running optimized...")
optimized_time = timeit.timeit(lambda: _parse_address_table_optimized(html_data, table_id, row_class), number=10)
print(f"Optimized (10 runs): {optimized_time:.4f}s")
print(f"Improvement: {(baseline_time - optimized_time) / baseline_time * 100:.2f}%")

res1 = _parse_address_table_unoptimized(html_data, table_id, row_class)
res2 = _parse_address_table_optimized(html_data, table_id, row_class)
assert res1 == res2, "Results do not match!"
print("Correctness verified!")
