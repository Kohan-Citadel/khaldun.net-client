## khaldun.net-client

khaldun.net-client is a modification for Kohan: Immortal Sovereigns and Kohan: Ahriman's Gift now-defunct GameSpy Arcade service with an open-source alternative.

This allows the multiplayer feature of these games to be used again.

The khaldun.net client module is unobtrusive, meaning no game files need to be altered. It is loaded into the game's memory and redirects the requests from GameSpy to the khaldun.net OpenSpy server on the fly. If the khaldun.net server is unavailable, it will connect to the openspy.net server instead. It is very light and does not carry any performance penalty.

The client module performs a server health check immediately upon startup. If one or both servers are down, you may experience up to a 10s delay as the client waits for a server response. If neither server is reachable, the client won't patch the server URL. This will result in the familiar "GameSpy DNS servers unreachable" error when entering the multiplayer lobby and will still allow direct connecting via IP.

Compatible with Windows XP / Vista / 7 / 8 / 8.1 / 10 / 11 and Server 2003 / 2003 R2 / 2008 / 2008 R2 / 2012 / 2012 R2 / 2016 / 2019 / 2022

## How to install

1. Download the [latest release](https://github.com/Kohan-Citadel/khaldun.net-client/releases/latest/download/khaldun.net.zip)

2. Extract the `dinput.dll` file to the game folder, next to the game executable.   

3. Play !

## Remarks
To uninstall, simply delete the `dinput.dll` file.

---

:earth_americas: [Web](https://beta.openspy.net/) &emsp;
<img alt="Discord" src="https://user-images.githubusercontent.com/13628128/226210682-c9044ed1-e4d9-431c-b085-1d684a9f9942.png" width="20" height="20"> [Discord](http://discord.gg/sMaWdbt)

This component is a part of the [OpenSpy](https://beta.openspy.net/) project

- [openspy-core-v2](https://github.com/chc/openspy-core-v2)
- [openspy-web-backend](https://github.com/chc/openspy-web-backend)
- [openspy-natneg-helper](https://github.com/chc/openspy-natneg-helper)
- [openspy-discord-bot](https://github.com/chc/openspy-discord-bot)
- openspy-client

