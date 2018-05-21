cd ..\..\
D:\python35\python setup.py install
cd contrib\build-wine\
D:\python35\scripts\pyinstaller --noconfirm --ascii --name electrum-mlm-3.1.4 -w deterministic.spec
"c:\Program Files (x86)\NSIS\makensis.exe" /DPRODUCT_VERSION=3.1.4 electrum-windows.nsi