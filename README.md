# HxYXDriver

A simple driver for hacking.

## Get Started

1. Install Visual Studio 2015
2. Modify vs2015, add Windows SDK feature
3. Open project by double click HxYXDriver.sln
4. Choose compile target to x64 Release
5. You are good to go, enjoy!

## Use the Driver

Use [DSEFix](https://github.com/hfiref0x/DSEFix) to enable system to load vulnerable drivers:

```
start dsefix.exe
sc create hxyx binpath=Driver.sys type=kernel
sc start hxyx
start dsefix.exe -e
```

to unload the driver:

```
sc stop hxyx
```

to delete driver:

```
sc delete stop
```
