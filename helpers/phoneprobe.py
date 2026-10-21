"""
Hashling phone check-up probe for iPhone and iPad (read-only).

Reads what a trusted iPhone or iPad tells this Mac over the USB cable, with the
open-source pymobiledevice3 library, and prints one JSON document:
device details, apps installed outside the App Store, configuration profiles,
provisioning profiles and remote-management (MDM) enrollment.

It only ever asks the phone questions. It never pairs, installs, removes or
changes anything, and nothing it reads leaves this Mac.

Usage: python -I phoneprobe.py <udid> <pairing-cache-dir>
"""
import asyncio
import base64
import datetime
import json
import sys
from pathlib import Path

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.misagent import MisagentService
from pymobiledevice3.services.mobile_config import MobileConfigService

APP_ATTRS = [
    'CFBundleIdentifier', 'CFBundleDisplayName', 'CFBundleName', 'CFBundleShortVersionString',
    'SignerIdentity', 'ApplicationType', 'ProfileValidated', 'IsAppClip', 'IsUpgradeable',
]
DEVICE_KEYS = [
    'DeviceName', 'ProductType', 'ProductVersion', 'BuildVersion', 'DeviceClass', 'HardwareModel',
    'PasswordProtected', 'ActivationState', 'TimeZone', 'MarketingName',
]


def plain(v):
    """Make plist values JSON-safe (bytes become short base64, dates ISO strings)."""
    if isinstance(v, dict):
        return {str(k): plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [plain(x) for x in v]
    if isinstance(v, bytes):
        return {'bytes': len(v), 'b64': base64.b64encode(v[:64]).decode()}
    if isinstance(v, (datetime.datetime, datetime.date)):
        return v.isoformat()
    return v


async def step(out, name, fn):
    try:
        out[name] = plain(await asyncio.wait_for(fn(), timeout=60))
    except Exception as e:  # each part is optional; report what failed and carry on
        out.setdefault('errors', {})[name] = f'{type(e).__name__}: {e}'[:300]


async def main(udid: str, cache: str) -> None:
    out = {'udid': udid}
    try:
        lockdown = await create_using_usbmux(serial=udid, autopair=False, pairing_records_cache_folder=Path(cache))
    except Exception as e:
        print(json.dumps({'udid': udid, 'fatal': f'{type(e).__name__}: {e}'[:300]}))
        return
    if not getattr(lockdown, 'paired', False):
        await lockdown.close()
        print(json.dumps({'udid': udid, 'fatal': 'NotPaired: tap Trust on the phone first'}))
        return
    try:
        async def device():
            values = await lockdown.get_value()
            info = {k: values.get(k) for k in DEVICE_KEYS if k in values}
            for domain, keys in (('com.apple.disk_usage', ['TotalDataCapacity', 'TotalDataAvailable', 'TotalDiskCapacity']),
                                 ('com.apple.mobile.backup', ['WillEncrypt', 'LastCloudBackupDate', 'CloudBackupEnabled'])):
                try:
                    d = await lockdown.get_value(domain=domain) or {}
                    info.update({k: d.get(k) for k in keys if k in d})
                except Exception:
                    pass
            return info

        async def apps():
            svc = InstallationProxyService(lockdown=lockdown)
            return await svc.browse(options={'ApplicationType': 'User'}, attributes=APP_ATTRS)

        async def profiles():
            return await MobileConfigService(lockdown=lockdown).get_profile_list()

        async def cloud():
            return await MobileConfigService(lockdown=lockdown).get_cloud_configuration()

        async def provisioning():
            items = []
            for p in await MisagentService(lockdown=lockdown).copy_all():
                pl = p.plist
                ent = pl.get('Entitlements') or {}
                items.append({
                    'name': pl.get('Name'), 'team': pl.get('TeamName'), 'app': pl.get('AppIDName'),
                    'expires': pl.get('ExpirationDate'), 'created': pl.get('CreationDate'),
                    'allDevices': bool(pl.get('ProvisionsAllDevices')),
                    'devices': len(pl.get('ProvisionedDevices') or []),
                    'getTaskAllow': bool(ent.get('get-task-allow')),
                    'betaReports': bool(ent.get('beta-reports-active')),
                })
            return items

        await step(out, 'device', device)
        await step(out, 'apps', apps)
        await step(out, 'profiles', profiles)
        await step(out, 'cloud', cloud)
        await step(out, 'provisioning', provisioning)
    finally:
        try:
            await lockdown.close()
        except Exception:
            pass
    print(json.dumps(out))


if __name__ == '__main__':
    asyncio.run(main(sys.argv[1], sys.argv[2]))
