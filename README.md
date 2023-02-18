# Threadless Inject BOF

A beacon object file implementation of [ThreadlessInject](https://github.com/CCob/ThreadlessInject) by [@\_EthicalChaos\_](https://twitter.com/_EthicalChaos_), making use of API hashing and calling NTAPI functions directly rather than going through the Windows API.

ThreadlessInject is a novel process injection technique involving hooking an export function from a remote process in order to gain shellcode execution. The original project was released after their talk at BSides Cymru 2023.

_Note: I made this project in order to learn how to write BOF's, so this hasn't been thoroughly tested._

## Usage

```
threadless-inject <pid> <dll> <export function> <shellcode path>
```

### Examples

For sake of example, all process id's have been assumed to be `1234`.

**Inject into chrome.exe, execute shellcode when process closes**
```
threadless-inject 1234 ntdll.dll NtTerminateProcess shellcode.bin
```

**Inject into notepad.exe, execute upon file open**
```
threadless-inject 1234 ntdll.dll NtOpenFile shellcode.bin
```

## Credits

- [@\_EthicalChaos\_](https://twitter.com/_EthicalChaos_) - Creator of [ThreadlessInject](https://github.com/CCob/ThreadlessInject)  
- [@shubakki](https://twitter.com/shubakki) - Helped port some helper functions, such as `findMemoryHole`