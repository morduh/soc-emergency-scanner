# -*- mode: python ; coding: utf-8 -*-
#
# ─────────────────────────────────────────────────────────────────────────────
# SOC-Scanner.spec — FOR DEVELOPERS ONLY
#
# PURPOSE : PyInstaller build configuration used to package app.py and the
#           compiled React frontend into a single standalone SOC-Scanner.exe.
#           Only needed if you are rebuilding the exe from source.
#           End users do NOT need this file — SOC-Scanner.exe is already
#           included in the repository and ready to use.
#
# HOW TO USE:
#   pyinstaller SOC-Scanner.spec
#   (or just run build_exe.bat which handles everything automatically)
# ─────────────────────────────────────────────────────────────────────────────


a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=[('frontend\\build', 'frontend\\build')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SOC-Scanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
