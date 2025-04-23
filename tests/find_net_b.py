import pcapy
import winreg

def get_device_names():
    devices = pcapy.findalldevs()
    for dev in devices:
        name = get_friendly_name(dev)
        print(f"{dev} => {name}")

def get_friendly_name(dev_path):
    try:
        # Trích ID từ chuỗi NPF
        dev_id = dev_path.split('{')[-1].split('}')[0]
        key_path = f"SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as base_key:
            for i in range(0, 9999):
                try:
                    subkey_name = f"{i:04}"
                    with winreg.OpenKey(base_key, subkey_name) as subkey:
                        val, _ = winreg.QueryValueEx(subkey, "NetCfgInstanceId")
                        if val.lower() == dev_id.lower():
                            friendly_name, _ = winreg.QueryValueEx(subkey, "DriverDesc")
                            return friendly_name
                except FileNotFoundError:
                    break
                except Exception:
                    continue
    except Exception:
        return "Unknown"
    return "Unknown"

get_device_names()
