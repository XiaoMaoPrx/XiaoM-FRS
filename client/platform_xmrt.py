import os
import re
import sys
try:
    import _wmi
except ImportError:
    _wmi = None
_WIN32_CLIENT_RELEASES = [
    ((10, 1, 0), "post11"),
    ((10, 0, 22000), "11"),
    ((6, 4, 0), "10"),
    ((6, 3, 0), "8.1"),
    ((6, 2, 0), "8"),
    ((6, 1, 0), "7"),
    ((6, 0, 0), "Vista"),
    ((5, 2, 3790), "XP64"),
    ((5, 2, 0), "XPMedia"),
    ((5, 1, 0), "XP"),
    ((5, 0, 0), "2000"),
]
_WIN32_SERVER_RELEASES = [
    ((10, 1, 0), "post2025Server"),
    ((10, 0, 26100), "2025Server"),
    ((10, 0, 20348), "2022Server"),
    ((10, 0, 17763), "2019Server"),
    ((6, 4, 0), "2016Server"),
    ((6, 3, 0), "2012ServerR2"),
    ((6, 2, 0), "2012Server"),
    ((6, 1, 0), "2008ServerR2"),
    ((6, 0, 0), "2008Server"),
    ((5, 2, 0), "2003Server"),
    ((5, 0, 0), "2000Server"),
]
_uname_cache = None
def _wmi_query(table, *keys):
    global _wmi
    if not _wmi:
        raise OSError("not supported")
    table = {
        "OS": "Win32_OperatingSystem",
        "CPU": "Win32_Processor",
    }[table]
    try:
        data = _wmi.exec_query("SELECT {} FROM {}".format(
            ",".join(keys),
            table,
        )).split("\0")
    except OSError:
        _wmi = None
        raise OSError("not supported")
    split_data = (i.partition("=") for i in data)
    dict_data = {i[0]: i[2] for i in split_data}
    return (dict_data[k] for k in keys)
def _syscmd_ver(system='', release='', version='',
               supported_platforms=('win32', 'win16', 'dos')):
    if sys.platform not in supported_platforms:
        return system, release, version
    import subprocess
    for cmd in ('ver', 'command /c ver', 'cmd /c ver'):
        try:
            info = subprocess.check_output(cmd,
                                           stdin=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL,
                                           text=True,
                                           encoding="locale",
                                           shell=True)
        except (OSError, subprocess.CalledProcessError) as why:
            continue
        else:
            break
    else:
        return system, release, version
    ver_output = re.compile(r'(?:([\w ]+) ([\w.]+) '
                         r'.*'
                         r'\[.* ([\d.]+)\])')
    info = info.strip()
    m = ver_output.match(info)
    if m is not None:
        system, release, version = m.groups()
        if release[-1] == '.':
            release = release[:-1]
        if version[-1] == '.':
            version = version[:-1]
        version = _norm_version(version)
    return system, release, version
def _norm_version(version, build=''):
    l = version.split('.')
    if build:
        l.append(build)
    try:
        strings = list(map(str, map(int, l)))
    except ValueError:
        strings = l
    version = '.'.join(strings[:3])
    return version
def _get_machine_win32():
    try:
        [arch, *_] = _wmi_query('CPU', 'Architecture')
    except OSError:
        pass
    else:
        try:
            arch = ['x86', 'MIPS', 'Alpha', 'PowerPC', None,
                    'ARM', 'ia64', None, None,
                    'AMD64', None, None, 'ARM64',
            ][int(arch)]
        except (ValueError, IndexError):
            pass
        else:
            if arch:
                return arch
    return (
        os.environ.get('PROCESSOR_ARCHITEW6432', '') or
        os.environ.get('PROCESSOR_ARCHITECTURE', '')
    )
def _win32_ver(version, csd, ptype):
    try:
        (version, product_type, ptype, spmajor, spminor)  = _wmi_query(
            'OS',
            'Version',
            'ProductType',
            'BuildType',
            'ServicePackMajorVersion',
            'ServicePackMinorVersion',
        )
        is_client = (int(product_type) == 1)
        if spminor and spminor != '0':
            csd = f'SP{spmajor}.{spminor}'
        else:
            csd = f'SP{spmajor}'
        return version, csd, ptype, is_client
    except OSError:
        pass
def win32_ver(release='', version='', csd='', ptype=''):
    is_client = False
    version, csd, ptype, is_client = _win32_ver(version, csd, ptype) # type: ignore
    if version:
        intversion = tuple(map(int, version.split('.')))
        releases = _WIN32_CLIENT_RELEASES if is_client else _WIN32_SERVER_RELEASES
        release = next((r for v, r in releases if v <= intversion), release)
    return release, version, csd, ptype
def xmplatform():
    global _uname_cache
    if _uname_cache is not None:
        return _uname_cache
    try:
        system, node, release, version, machine = infos = os.uname() # type: ignore
    except AttributeError:
        system = sys.platform
        try:
            import socket
            node = socket.gethostname()
        except (ImportError, OSError):
            node = ''
        release = version = machine = ''
        infos = ()
    if not any(infos):
        if system == 'win32':
            release, version, csd, ptype = win32_ver()
            machine = machine or _get_machine_win32()
        if not (release and version):
            system, release, version = _syscmd_ver(system)
            if system == 'Microsoft Windows':
                system = 'Windows'
            elif system == 'Microsoft' and release == 'Windows':
                system = 'Windows'
                if '6.0' == version[:3]:
                    release = 'Vista'
                else:
                    release = ''
        if system in ('win32', 'win16'):
            if not version:
                if system == 'win32':
                    version = '32bit'
                else:
                    version = '16bit'
            system = 'Windows'
    if system == 'OpenVMS':
        if not release or release == '0':
            release = version
            version = ''
    if system == 'Microsoft' and release == 'Windows':
        system = 'Windows'
        release = 'Vista'
    if sys.platform == 'android':
        system = 'Android'
        release = android_ver().release
    if sys.platform == 'ios':
        system, release, _, _ = ios_ver()
    details = {
        'system': system,
        'node': node,
        'release': release,
        'version': version,
        'machine': machine
    }
    return details