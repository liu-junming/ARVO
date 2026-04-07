import requests
# obsolete url format: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=30419
import re
from datetime import datetime
from .utils_log import *
from .utils import *
import json
from google.cloud import storage
from urllib.parse import urlparse
from urllib.parse import parse_qs
import hashlib 
if NEW_ISSUE_TRACKER:
    META = ARVO / NEW_ISSUE_TRACKER
def metaFilter():
    localIds = getAllLocalIds()[::-1]
    res = []
    # nonC = []
    broken_srcmaps = []
    false_positives = []
    for localId in localIds:
        target_dir = Path(DATADIR)/"Issues"/(str(localId)+"_files")
        if len(list(target_dir.iterdir())) <2:
            res.append(localId)
            WARN(f"[!] Have less than 2 srcmaps, deleting issue {localId}...")
            continue
        srcmap = getSrcmaps(localId)
        # Filter out Borken srcmap
        out = False
        for x in srcmap:
            with open(x) as f:
                data = json.loads(f.read())
            for key in data.keys():
                item = data[key]
                values = list(item.values())
                if "unknown" in values or "UNKNOWN" in values:
                    broken_srcmaps.append(localId)
                    out = True
                    break
            if out == True:
                break

        # Filter out the false positive cases:
        tmp_lst = []
        for y in srcmap:
            file_hash = hashlib.md5()
            with open(y,'rb') as f:
                file_hash.update(f.read())
            tmp_lst.append(file_hash.digest())
        if len(set(tmp_lst)) != len(tmp_lst):
            false_positives.append(localId)
    res.extend(broken_srcmaps)
    # print(false_positives)
    # res.extend(false_positives)
    res = list(set(res))
    remove_issue_meta(res)
    remove_issue_data(res)
def getIssueIds():
    localIds = []
    session = requests.Session()
    # Step 1: Get the token from the cookie
    session.get("https://issues.oss-fuzz.com/")
    xsrf_token = session.cookies.get("XSRF_TOKEN")
    # Step 2: Use it in the header
    headers = {
        'Content-Type': 'application/json',
        'Origin': 'https://issues.oss-fuzz.com',
        'Referer': 'https://issues.oss-fuzz.com/',
        'X-XSRF-Token': xsrf_token
    }
    url = 'https://issues.oss-fuzz.com/action/issues/list'
    start_index = 0
    start_year  = 2016
    next_year   = datetime.now().year + 1
    while start_year != next_year:
        init_num = len(localIds)
        start_index = 0
        while True:
            end_year = start_year +1
            data = [None, None, None, None, None, ["391"], [f"type:vulnerability status:verified created<{end_year}-01-01 created>{start_year}-01-01", None, 500, f"start_index:{start_index}"]]
            response = session.post(url, headers=headers, json=data)
            data = response.text
            # Fix malformed JSON-like string
            clean_data = re.sub(r'\bnull\b', 'null', data)
            clean_data = clean_data.replace("'", '"')
            clean_data = re.sub(r',\s*]', ']', clean_data)
            # Parse with regex (quick and dirty)
            issues = re.findall(r'\[\s*null\s*,\s*(\d+),\s*\[\d+,\d+,\d+,\d+,\d+,"(.*?)"', clean_data)
            
            for issue_id, title in issues:
                localIds.append(issue_id)
            if len(issues)!=500:
                break
            start_index+=500
            if (len(localIds) - init_num == 2500):
                WARN("Out of Limit. Not Supported yet. (You may split it by month instead of year)")
                exit(1)
        added_num = len(localIds) - init_num
        SUCCESS(f"[+] Added {added_num:,} issues from {start_year} ({len(localIds):,} total)")
        start_year+=1
    
    return [int(x) for x in localIds]

def parse_oss_fuzz_report(report_text: bytes,localId: int) -> dict:
    text = report_text.decode('unicode_escape', errors='ignore')  # decode escaped unicode like \u003d
    def extract(pattern,default=''):
        m = re.search(pattern, text)
        if not m:
            if default=='':
                WARN(f"FAILED to PARSE {pattern} {localId=}")
                exit(1)
            else:
                return default
        return m.group(1).strip()
    res = {
        "project": extract(r'(?:Target|Project):\s*(\S+)','NOTFOUND'),
        "job_type": extract(r'Job Type:\s*(\S+)'),
        "platform": extract(r'Platform Id:\s*(\S+)','linux'),
        "crash_type": extract(r'Crash Type:\s*(.+)'),
        "crash_address": extract(r'Crash Address:\s*(\S+)'),
        "severity": extract(r'Security Severity:\s*(\w+)', 'Medium'),
        "regressed": extract(r'(?:Regressed|Crash Revision):\s*(https?://\S+)',"NO_REGRESS"),
        "reproducer": extract(r'(?:Minimized Testcase|Reproducer Testcase|Download).*:\s*(https?://\S+)'),
        "verified_fixed": extract(r'(?:fixed in|Fixed:)\s*(https?://\S+revisions\S+)','NO_FIX'),
        "localId": localId
    }
    sanitizer_map = {
        "address (ASAN)": "address",
        "memory (MSAN)": "memory",
        "undefined (UBSAN)": "undefined",
        "asan": "address",
        "msan": "memory",
        "ubsan": "undefined",
    }
    fuzz_target = extract(r'(?:Fuzz Target|Fuzz target|Fuzz target binary|Fuzzer):\s*(\S+)','NOTFOUND')
    if len(res['job_type'].split("_"))==2:
        WARN(f"FAILED to GET sanitizer {localId=} {res['job_type']}")
        return False
    else:
        res['sanitizer'] = sanitizer_map[res['job_type'].split("_")[1]]

    if fuzz_target != 'NOTFOUND':
        res['fuzz_target'] = fuzz_target
    if res['project'] == "NOTFOUND":
        res['project'] = res['job_type'].split("_")[-1]
    return res
def _meta_getIssue_html(issue_id, session):
    """Fallback parser for new-format issues whose /events endpoint returns 404.

    The issue HTML page embeds the same ClusterFuzz report text and additionally
    contains the verified-fixed revision URL as a second distinct 'range=' link.
    """
    r = session.get(f'https://issues.oss-fuzz.com/issues/{issue_id}')
    if r.status_code != 200:
        WARN(f"[HTML fallback] HTTP {r.status_code} for issue {issue_id}")
        return False
    page = r.text

    # Extract the ClusterFuzz report block (from "Fuzz Target:" to "Issue filed")
    idx_start = page.find('Fuzz Target:')
    idx_end   = page.find('Issue filed automatically')
    if idx_start == -1 or idx_end == -1:
        WARN(f"[HTML fallback] Cannot locate report block for {issue_id}")
        return False
    report_text = page[idx_start:idx_end]
    report_bytes = report_text.encode('utf-8', errors='ignore')

    try:
        res = parse_oss_fuzz_report(report_bytes, issue_id)
    except Exception:
        WARN(f"[HTML fallback] parse_oss_fuzz_report failed for {issue_id}")
        return False
    if not res:
        return False

    # Fix project: the HTML report page shows "Fuzz Target: <fuzzer>" rather than
    # "Project: <project>", so parse_oss_fuzz_report matches the fuzzer name.
    # Always re-derive the project from the job_type suffix for new-format issues.
    job_type = res.get('job_type', '')
    if job_type:
        parsed_job = parse_job_type(job_type)
        if 'project' in parsed_job:
            res['project'] = parsed_job['project']

    # Extract verified_fixed from the second distinct revision URL in the page.
    if res.get('verified_fixed') == 'NO_FIX':
        page_dec = page.replace(r'\u003d', '=').replace(r'\u0026', '&')
        # Collect revision URLs that contain 'range=' and no HTML-entity ampersand
        revisions = list(dict.fromkeys(
            u for u in re.findall(r'https://oss-fuzz\.com/revisions\?[^\s"\\<]+', page_dec)
            if 'range=' in u and '&amp;' not in u
        ))
        if len(revisions) >= 2:
            res['verified_fixed'] = revisions[1]

    return res

def meta_getIssue(issue_id):
    session = requests.Session()
    # Step 1: Get the token from the cookie
    session.get("https://issues.oss-fuzz.com/")
    xsrf_token = session.cookies.get("XSRF_TOKEN")
    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en,zh-CN;q=0.9,zh;q=0.8,ar;q=0.7',
        'priority': 'u=1, i',
        'referer': 'https://issues.oss-fuzz.com/',
        'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Linux"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
        'X-XSRF-Token': xsrf_token
    }
    # Step 2: Try the events endpoint (works for legacy issues)
    url = f'https://issues.oss-fuzz.com/action/issues/{issue_id}/events?currentTrackerId=391'
    response = session.get(url, headers=headers)
    if response.status_code == 404:
        # New issue format: fall back to HTML page parsing
        return _meta_getIssue_html(issue_id, session)
    raw_text = response.content
    try:
        res = parse_oss_fuzz_report(raw_text, issue_id)
    except Exception:
        WARN(f"FAIL on {issue_id}, skip")
        return False
    return res
def meta_getIssues(issue_ids):
    issues = []
    if not MetaDataFile.exists():
        MetaDataFile.touch()
    done = []
    with open(MetaDataFile,'r') as f:
        lines = f.readlines()
    for line in lines:
        done.append(json.loads(line)['localId'])
    todo = [x for x in issue_ids if x not in done]
    INFO(f"Added {len(todo)} new issues")
    for x in bar(todo):
        res = meta_getIssue(x)
        if res:
            issues.append(res)
            with open(MetaDataFile,'a') as f:
                f.write(json.dumps(res) + '\n') 
        else:
            WARN(f"Failed to fetch the issue for {x}")
    return todo
# Parse the job type into parts
def parse_job_type(job_type):
    parts = job_type.split('_')
    remainder = []
    parsed = {}
    while len(parts) > 0:
        part = parts.pop(0)
        if part in ['afl', 'honggfuzz', 'libfuzzer']:
            parsed['engine'] = part
        elif part in ['asan', 'ubsan', 'msan']:
            parsed['sanitizer'] = part
        elif part == 'i386':
            parsed['arch'] = part
        elif part == 'untrusted':
            parsed['untrusted'] = True
        else:
            remainder.append(part)
    if len(remainder) > 0:
        parsed['project'] = '_'.join(remainder)
    if 'arch' not in parsed:
        parsed['arch'] = 'x86_64'
    if 'engine' not in parsed:
        parsed['engine'] = 'none'
    if 'untrusted' not in parsed:
        parsed['untrusted'] = False
    return parsed
storage_client = None
def download_build_artifacts(metadata, url, outdir):
    global storage_client
    if storage_client is None:
        # clusterfuzz-builds buckets are publicly readable; use anonymous credentials
        # to avoid needing a quota project from the caller's GCP account.
        from google.auth.credentials import AnonymousCredentials
        storage_client = storage.Client(credentials=AnonymousCredentials(), project='oss-fuzz')
    bucket_map = {
        "libfuzzer_address_i386": "clusterfuzz-builds-i386",
        "libfuzzer_memory_i386": "clusterfuzz-builds-i386",
        "libfuzzer_undefined_i386": "clusterfuzz-builds-i386",
        "libfuzzer_address": "clusterfuzz-builds",
        "libfuzzer_memory": "clusterfuzz-builds",
        "libfuzzer_undefined": "clusterfuzz-builds",
        "afl_address": "clusterfuzz-builds-afl",
        "honggfuzz_address": "clusterfuzz-builds-honggfuzz",
    }
    sanitizer_map = {
        "address (ASAN)": "address",
        "memory (MSAN)": "memory",
        "undefined (UBSAN)": "undefined",
        "asan": "address",
        "msan": "memory",
        "ubsan": "undefined",
        "address": "address",
        "memory": "memory",
        "undefined": "undefined",
        None: "",
    }
    job_name = metadata["job_type"]
    job = parse_job_type(job_name)
    
    # These don't have any build artifacts
    if job['untrusted']: return False
    if job['engine'] == 'none': return False
    # Prefer the info from the job name, since the metadata
    # format has changed several times.
    if 'project' in metadata:
        project = metadata["project"]
    else:
        project = job['project']
    if 'sanitizer' in metadata:
        sanitizer = sanitizer_map[metadata["sanitizer"]]
        assert sanitizer == sanitizer_map[job['sanitizer']]
    else:
        sanitizer = sanitizer_map[job['sanitizer']]
    fuzzer = job['engine']
    bucket_string = f"{fuzzer}_{sanitizer}"
    if job['arch'] == 'i386':
        bucket_string += '_i386'
    assert bucket_string in bucket_map
    bucket_name = bucket_map[bucket_string]

    # Grab the revision from the URL
    urlparams = parse_qs(urlparse(url).query)
    
    if 'revision' in urlparams:
        revision = urlparams['revision'][0]
    elif 'range' in urlparams:
        revision = urlparams['range'][0].split(':')[1]
    else:
        return False
    
    zip_name = f'{project}-{sanitizer}-{revision}.zip'
    srcmap_name = f'{project}-{sanitizer}-{revision}.srcmap.json'
    zip_path = f'{project}/{zip_name}'
    srcmap_path = f'{project}/{srcmap_name}'
    downloaded_files = []
    bucket = storage_client.bucket(bucket_name)
    for path, name in [(srcmap_path, srcmap_name)]:
#    for path, name in [(zip_path, zip_name), (srcmap_path, srcmap_name)]:

        download_path = outdir / name

        if download_path.exists():
            print(f'Skipping {name} (already exists)')
            downloaded_files.append(download_path)
            continue
        blob = bucket.blob(path)
        if not blob.exists():
            print(f'Skipping {name} (not found)')
            continue
        print(download_path)
        blob.download_to_filename(str(download_path))
        
        print(f'Downloaded {name}')
        downloaded_files.append(download_path)
    return [str(f) for f in downloaded_files]
def data_download(localIds = None):
    metadata = {}
    for line in open(MetaDataFile):
        line = json.loads(line)
        if localIds == None or line['localId'] in localIds:
            metadata[line['localId']] = line
    to_remove = []
    for localId in bar(metadata):
        # Get reproducer(s) and save them.
        issue_dir = META / "Issues" / f"{localId}_files"
        if issue_dir.exists():
            done = []
            for x in issue_dir.iterdir():
                done.append(x)
            if len(done) == 2:
                continue
            elif len(done) != 0:
                shutil.rmtree(issue_dir)
        issue_dir.mkdir(parents=True, exist_ok=True)
        if 'regressed' not in metadata[localId] or 'verified_fixed' not in metadata[localId] or \
            metadata[localId]['verified_fixed'] == 'NO_FIX':
            continue
        # Fast language check from the metadata dict (avoids needing srcmaps on disk).
        # Falls back to getLanguage() for projects not in the PLanguage cache.
        _pname = metadata[localId].get('project')
        if _pname and _pname in PLanguage:
            _lang = PLanguage[_pname]
        else:
            _lang = getLanguage(str(localId))
        if _lang not in ['c','c++']:
            WARN(f"[!] Not C/C++ Issue: {localId=}")
            to_remove.append(localId)
            continue
        if not silentRun(download_build_artifacts,metadata[localId], metadata[localId]['regressed'], issue_dir): 
            WARN(f"[!] Failed to download the srcmap: {localId=}")
            to_remove.append(localId)
            continue
        if not silentRun(download_build_artifacts,metadata[localId], metadata[localId]['verified_fixed'], issue_dir):
            WARN(f"[!] Failed to download the srcmap: {localId=}")
            to_remove.append(localId)
            continue


    remove_issue_meta(to_remove)
    remove_issue_data(to_remove)
    return True
def getMeta():
    if not NEW_ISSUE_TRACKER: PANIC("THIS SCRIPT ONLY WORKS FOR NEW_ISSUE_TRACKER")
    if not META.exists(): META.mkdir()
    todo = meta_getIssues(getIssueIds())
    print(todo)
    data_download(todo)

if __name__ == "__main__":
    pass
