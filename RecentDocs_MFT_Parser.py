# recentdocs_analyzer_mft_verified_csv.py
from regipy.registry import RegistryHive
from regipy.exceptions import RegistryKeyNotFoundException
from datetime import datetime, timedelta
import argparse
import struct
import sys
import subprocess
import csv
import os

class FileEntry:
    def __init__(self, fname_str, position):
        self.fname = fname_str
        self.ftimestamp = None
        self.position = position
        self.is_deleted = False
        
def convert_wintime(wintime):
    """Converts a Windows FILETIME integer into a human-readable string."""
    try:
        wintime = int(wintime)
        microseconds = wintime / 10
        dt = datetime(1601, 1, 1) + timedelta(microseconds=microseconds)
        return dt.strftime('%Y-%m-%d %H:%M:%S.%f')
    except:
        return None        

def parse_MRUListEx(mrulist):
    if not mrulist:
        return []
    
    # regipy often returns REG_BINARY as a hex string. We must convert it back to bytes.
    if isinstance(mrulist, str):
        try:
            mrulist = bytes.fromhex(mrulist)
        except ValueError:
            mrulist = mrulist.encode('latin-1', errors='ignore')
            
    if not isinstance(mrulist, bytes):
        return []

    # Strip the trailing 0xFF bytes which signal the end of the MRU list
    mrulist = mrulist.rstrip(b'\xff')
    
    size = len(mrulist) // 4
    if size <= 0:
        return []
    return struct.unpack("%sI" % size, mrulist)

def extract_mft_records(mft_path):
    """Uses analyzeMFT to parse the $MFT and returns a list of all files."""
    temp_csv = "temp_mft_output_internal.csv"
    mft_records = []
    
    print(f"[*] Running analyzeMFT on {mft_path}... this may take a moment.")
    try:
        subprocess.run(
            ['analyzeMFT', '-f', mft_path, '-o', temp_csv], 
            check=True, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        
        with open(temp_csv, 'r', encoding='utf-8', errors='replace') as csvfile:
            reader = csv.reader(csvfile)
            try:
                headers = next(reader)
            except StopIteration:
                print("[!] ERROR: MFT CSV output is empty.")
                return []
                
            filename_idx = None
            for i, h in enumerate(headers):
                if h and 'ilename' in h.lower():
                    filename_idx = i
                    break
                    
            if filename_idx is None:
                print("[!] ERROR: Could not locate a Filename column in MFT output.")
                return []
                
            status_idx = None
            for i, h in enumerate(headers):
                h_lower = h.lower()
                if h_lower in ['active', 'allocated', 'status', 'in use']:
                    status_idx = i
                    break
            
            if status_idx is None and len(headers) > 2:
                status_idx = 2
                
            for row in reader:
                if len(row) > filename_idx:
                    original_name = row[filename_idx].strip()
                    if original_name:
                        active_status = row[status_idx].strip().lower() if (status_idx is not None and len(row) > status_idx) else ''
                        is_deleted = any(word in active_status for word in ['inactive', 'not in use', 'unallocated', 'false'])
                        
                        mft_records.append((original_name.lower(), original_name, is_deleted))
                        
    except Exception as e:
        print(f"[!] ERROR parsing MFT: {e}")
        sys.exit(1)
    finally:
        if os.path.exists(temp_csv):
            os.remove(temp_csv)
            
    return mft_records

def decode_registry_string(binary_data):
    """Safely decodes UTF-16 registry data, handling regipy hex string outputs."""
    if not binary_data:
        return "[ERROR]"
        
    # Convert hex string back to bytes if regipy converted it
    if isinstance(binary_data, str):
        try:
            binary_data = bytes.fromhex(binary_data)
        except ValueError:
            return binary_data.split('\x00')[0].strip()

    if not isinstance(binary_data, bytes):
        return "[ERROR]"
        
    try:
        full_str = binary_data.decode('utf-16', errors='ignore')
        return full_str.split('\x00')[0].strip()
    except:
        return "[ERROR]"

def main():
    parser = argparse.ArgumentParser(description='RecentDocs Forensic Analyzer with MFT Auto-Complete (regipy & CSV)')
    parser.add_argument('-f', '--file', required=True, help='Path to NTUSER.DAT')
    parser.add_argument('-o', '--output', required=True, help='Output CSV report file')
    parser.add_argument('-m', '--mft', required=False, help='Path to $MFT for verification')
    args = parser.parse_args()
    
    mft_records = []
    if args.mft:
        if not os.path.exists(args.mft):
            print(f"[!] ERROR: MFT file not found at {args.mft}")
            sys.exit(1)
        mft_records = extract_mft_records(args.mft)
        print(f"[*] Successfully loaded {len(mft_records)} total file records from the $MFT.")
    
    print(f"[*] Parsing Registry Hive with regipy: {args.file}")
    reg = RegistryHive(args.file)
    
    try:
        key_path = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        key = reg.get_key(key_path)
    except RegistryKeyNotFoundException:
        print("[!] ERROR: RecentDocs key not found in the provided hive.")
        sys.exit(1)
    
    recentdocs_values = {v.name: v.value for v in key.iter_values()}
    MRUListEx = parse_MRUListEx(recentdocs_values.get('MRUListEx'))
    
    recent = []
    for idx, r in enumerate(MRUListEx):
        try:
            value_data = recentdocs_values.get(str(r))
            fname_str = decode_registry_string(value_data)
            if fname_str:
                recent.append(FileEntry(fname_str, idx))
        except:
            recent.append(FileEntry("[ERROR]", idx))
    
    if recent:
        recent[0].ftimestamp = convert_wintime(key.header.last_modified)
    
    timestamped_positions = [0]
    for subkey in key.iter_subkeys():
        if subkey.name == 'Folder':
            continue
        try:
            sub_values = {v.name: v.value for v in subkey.iter_values()}
            subMRUListEx = parse_MRUListEx(sub_values.get('MRUListEx'))
            if subMRUListEx:
                mru0 = str(subMRUListEx[0])
                value_data = sub_values.get(mru0)
                mru0_filename = decode_registry_string(value_data)
                
                for i, entry in enumerate(recent):
                    if entry.fname == mru0_filename:
                        entry.ftimestamp = convert_wintime(subkey.header.last_modified)
                        timestamped_positions.append(i)
        except:
            continue
    
    timestamped_positions.sort()
    
    print(f"[*] Generating CSV Report: {args.output}")
    with open(args.output, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        
        writer.writerow(['Timestamp', 'File Name', 'Status'])
        
        for i, entry in enumerate(recent):
            filename = entry.fname
            
            if entry.ftimestamp is not None:
                timestamp = f'="{entry.ftimestamp}"'
            else:
                prev_ts = None
                next_ts = None
                for pos in timestamped_positions:
                    if pos < i:
                        prev_ts = recent[pos].ftimestamp
                    elif pos > i and next_ts is None:
                        next_ts = recent[pos].ftimestamp
                
                if prev_ts and next_ts:
                    timestamp = f"[INFERRED between {prev_ts} and {next_ts}]"
                elif prev_ts:
                    timestamp = f"[INFERRED after {prev_ts}]"
                elif next_ts:
                    timestamp = f"[INFERRED before {next_ts}]"
                else:
                    timestamp = "[INFERRED]"
            
            display_name = filename
            status_flag = ""
            is_system_folder = any(x in filename.lower() for x in ['this pc', 'desktop', 'internet'])
            
            if args.mft:
                reg_base, reg_ext = os.path.splitext(filename.lower())
                found_in_mft = False
                
                best_mft_match_deleted = False
                best_mft_original_name = filename
                
                for mft_lower, mft_original, is_deleted in mft_records:
                    mft_base, mft_ext = os.path.splitext(mft_lower)
                    
                    if reg_base == mft_base and mft_ext.startswith(reg_ext):
                        found_in_mft = True
                        best_mft_original_name = mft_original
                        
                        if is_deleted:
                            best_mft_match_deleted = True
                            break
                
                if found_in_mft:
                    display_name = best_mft_original_name
                    if best_mft_match_deleted:
                        status_flag = "[VERIFIED DELETED IN MFT]"
                    else:
                        status_flag = "[NOT DELETED (Active in MFT)]"
                elif entry.ftimestamp is None and not is_system_folder:
                    status_flag = "[NOT FOUND IN MFT - POTENTIALLY WIPED/DELETED]"
            else:
                if entry.ftimestamp is None and not is_system_folder:
                    status_flag = "[HEURISTIC: POTENTIALLY DELETED]"
            
            writer.writerow([timestamp, display_name, status_flag])
    
    print(f"[*] Complete. Report written to {args.output}")

if __name__ == '__main__':
    main()