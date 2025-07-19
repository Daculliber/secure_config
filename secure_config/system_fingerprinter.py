import hashlib, os, platform
from datetime import datetime, time, timedelta

def compare_time(time1: time, time2: time, threshold: int) -> bool:
    """
    Compares two datetime.time objects to see if their absolute difference
    (considering wrap-around at midnight) is less than or equal to a given threshold.

    Args:
        time1 (datetime.time): The first time object.
        time2 (datetime.time): The second time object.
        threshold (datetime.timedelta): The maximum allowed difference.

    Returns:
        bool: True if the times are within the threshold, False otherwise.
    """
    threshold=timedelta(seconds=threshold)
    # Use a dummy date to convert time objects to datetime objects for subtraction.
    # The specific date doesn't matter, only the time component.
    dummy_date = datetime.min.date()

    dt1 = datetime.combine(dummy_date, time1)
    dt2 = datetime.combine(dummy_date, time2)

    # Calculate the direct absolute difference
    direct_difference = abs(dt1 - dt2)

    # Calculate the "wrap-around" difference (e.g., 23:00 and 01:00 is 2 hours, not 22)
    # This considers the shortest path around the 24-hour clock.
    # timedelta(days=1) represents 24 hours.
    wrap_around_difference = timedelta(days=1) - direct_difference

    # The actual shortest difference is the minimum of these two
    shortest_difference = min(direct_difference, wrap_around_difference)

    # Check if the shortest difference is within the specified threshold
    return shortest_difference <= threshold





def machine_fingerprint():
    """
    Generates a somewhat unique identifier for the system.
    This is for 'binding' the config to a specific machine.
    WARNING: This is NOT tamper-proof. A determined attacker can spoof this.
    For strong licensing, you'd need more robust hardware fingerprinting
    or online activation.
    """
    try:
        # Combine various system details
        system_info = (
            platform.node() +
            platform.system() +
            platform.machine() +
            str(platform.processor())
        )
        # On Windows, you might add something like:
        # import winreg
        # try:
        #     key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        #     product_id, _ = winreg.QueryValueEx(key, "ProductId")
        #     winreg.CloseKey(key)
        #     system_info += product_id
        # except Exception:
        #     pass

        # Hash it to make it fixed length and less identifiable directly
        return hashlib.sha256(system_info.encode("utf-8")).hexdigest()
    except Exception as e:
        print(f"Warning: Could not get system identifier: {e}. Using a fallback.")
        return "fallback_system_id" + hashlib.sha256(os.urandom(16)).hexdigest()

#print(machine_fingerprint())

def hash_string(string):
    return hashlib.sha256(string.encode("utf-8")).hexdigest()
#print(hash_string("D3E9-9824-RR4-3KCKKR4-33"))
#print(Ncrypt(hash_string("D3E9-9824-RR4-3KCKKR4-33"),"3765625"))

def encode_date():
    return str(datetime.now())

        
def compare_date_from_file(time_from_file,path,seconds):
    try:
        time_from_file=str(time_from_file)
        format_code = '%Y-%m-%d %H:%M:%S.%f' # Example format
        dt_from_file = datetime.fromisoformat(time_from_file)
        time_from_file = dt_from_file.time()

        tst=os.path.getctime(path)
        dt_from_mtime = datetime.fromtimestamp(tst)
        tst = dt_from_mtime.time()
        return compare_time(time_from_file,tst,seconds)
    except Exception as e:
        print(e)
        #return False #any error means the file was tempered with
        