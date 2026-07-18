# Recommended first ten commits

1. **`chore: establish public repository policy`**  
   Add license, security policy, CODEOWNERS, issue templates and protected-branch
   documentation.

2. **`build: pin Go 1.26.5 and NixOS 26.05`**  
   Complete `GO-001` and `NIX-001`; commit `go.sum` and `flake.lock`.

3. **`api: generate v1 host and guest protobuf contracts`**  
   Complete `PROTO-001`; add Buf lint and breaking checks.

4. **`cli: implement command tree and structured diagnostics`**  
   Complete `CLI-001`; no privileged behavior yet.

5. **`config: implement strict TOML and policy validation`**  
   Complete `CFG-001`; unknown fields and secrets fail.

6. **`nix: build common hardened guest image`**  
   Complete `NIX-002` and boot it under TCG.

7. **`nix: add XFCE workstation-basic image`**  
   Complete the first part of `NIX-003`; prove SPICE Unix display.

8. **`daemon: add authenticated Unix gRPC service`**  
   Complete `D-001` with fake orchestrator.

9. **`runtime: add session owner and QEMU dry-run model`**  
   Complete `D-002`; implement typed QEMU validation without launch.

10. **`runtime: boot and destroy one workstation session`**  
    Complete `D-003` for the minimal path, with crash-cleanup integration tests.

Do not begin torrent, scanner or USB work until commit 10 passes repeatably.
