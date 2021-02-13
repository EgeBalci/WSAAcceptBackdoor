# WSAAcceptBackdoor

This project is a POC implementation for a DLL implant that acts as a backdoor for `accept` Winsock API calls. Once the DLL is injected into the target process, every `accept` call is intercepted using the Microsoft's detour library and redirected into the `BackdooredAccept` function. When a socket connection with a pre-defined special source port is establised, `BackdooredAccept` function launches a `cmd.exe` process and binds the accepted socket to the process STD(OUT/IN) using a named pipe.


<p align="center">
  <img src="https://raw.githubusercontent.com/EgeBalci/WSAAcceptBackdoor/master/banner.png">
  <br/>
</p>

**Demo:** [TTMO-4](https://ttmo.re/)