# -*- mode: python ; coding: utf-8 -*-

import sys
from PyInstaller.utils.hooks import collect_all

block_cipher = None

# Collect all dependencies
data = []
binaries = []
hiddenimports = ['tkinter', 'crccheck']

for name in ['tkinter', 'crccheck']:
    tmp_ret = collect_all(name)
    datas, tmpy_bin, tmp_hiddenimports = tmp_ret
    data += datas
    binaries += tmpy_bin
    hiddenimports += tmp_hiddenimports

a = Analysis(
    ['crc_calculator.py'],
    pathex=[],
    binaries=binaries,
    datas=data,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CRCCalculator',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Changed back to False to hide the console window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
