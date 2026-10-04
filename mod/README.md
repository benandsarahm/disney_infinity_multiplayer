# Disney Infinity 3.0 (PC / Steam) — Local Split-Screen Co-op

Unofficial interoperability mod. **v1.0**

Restores local multiplayer on the PC port: enter a Toy Box **or a Play Set**,
press **START on controller 2**, and Player 2 drops in with **split-screen**,
each player on their own gamepad.

Player 2 can also **choose their character** with the shoulder buttons, and the
mod only lets them pick characters that are **valid for the current world** (in
an Inside Out Play Set only the Inside Out cast shows up, etc.).

It is a `bink2w32.dll` **proxy**: on launch it loads the mod, forwards all Bink
video to the renamed original, and waits for Start on controller 2 to run the
co-op sequence **in memory**. It does **not** modify the .exe, saves, online or
achievements. Reversible.

## Requirements
- Disney Infinity 3.0: Gold Edition (PC / Steam), legitimate copy.
- 2 Xbox-style controllers (XInput).
- Be **inside a Toy Box or a Play Set** (a game loaded) when you press Start.

## Install (1 minute)
1. Copy these files into the game folder (where `DisneyInfinity3.exe` is):
   `coop_bink2w32.dll`, `INSTALL.bat`, `UNINSTALL.bat`, `coop_p2.txt` (optional).
2. With the **game closed**, double-click `INSTALL.bat` (it backs up the original
   as `_bink2w32_orig.dll` and installs the mod).
3. Launch the game normally (via Steam).

## How to play
1. Enter a Toy Box or a Play Set.
2. Connect controller 2.
3. Press **START on controller 2** → Player 2 and the split-screen appear.

## Choosing Player 2's character (NEW)
With **controller 2**, once Player 2 has joined:
- **RB** (right shoulder) = **next** character
- **LB** (left shoulder) = **previous** character

The mod auto-discovers **every** character in the game and only cycles through
the ones **valid for the current world** (it skips the rest).

- **Auto-fix:** if you enter a Play Set with a character that isn't valid there,
  the mod automatically switches Player 2 to a valid one ~2 seconds after joining.
- **Starting character:** edit `coop_p2.txt` (next to the mod) with the SKU you
  want for P2 (see `CHARACTERS_SKU.txt`). Default: `f4308` (Anakin). If it isn't
  valid in the world, the auto-fix corrects it.

## Known limitations (v1)
- After P2 changes character, **Player 1 may appear as a translucent hologram.**
  Fix: Player 2 presses **START** once and P1 refreshes.
- **Re-joining P2 after leaving to another world** may not work in the same
  session. Fix: restart the game to re-join Player 2.
- In a Play Set, P2's character must belong to that franchise (the cycler handles
  this). If a model shows up "white", cycle to another character with RB/LB.

## Uninstall
- With the game closed, double-click `UNINSTALL.bat` (restores the original
  `bink2w32.dll`). Or: Steam → right-click the game → Properties → Installed
  Files → Verify integrity.

## How it works (brief)
- Proxy `bink2w32.dll` (compiled with Zig). On Start (controller 2) it calls the
  game's drop-in creator, then materializes P2's body with inline hooks.
- Character validation uses the game's own Lua VM: the mod hooks `lua_pcall` to
  run small Lua snippets (`Player_IsCharacterValid`) on the live game state, so
  the cycler only offers characters valid for the current world.
- Nothing is written to disk by the game on behalf of the mod; all changes are
  in-process and reverted by uninstalling.

## Credits
Co-op achieved by combining two reverse-engineering projects:
- **CrabeLoader / DisneyInfinity-SplitScreenMods** (LucasLhomme, "crabe_crabe" on
  Discord): the Player 2 "join" method (controller + viewport + split) and the
  map of the game's Lua API used to validate characters.
  <https://github.com/LucasLhomme/DisneyInfinity-SplitScreenMods>
- **This project:** Player 2 character materialization, the per-franchise
  character cycler, and the DLL mod that joins both halves and triggers it with
  Start on controller 2.

Educational, non-commercial interoperability project. Contains no game code or
assets. Disney Infinity and its brands belong to their owners. Use at your own risk.
