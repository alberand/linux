{
  description = "Linux Kernel development env";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nix-kernel-vm.url = "github:alberand/nix-kernel-vm";
    xfstests.url = "git+file:/home/alberand/Projects/xfstests-dev?shallow=1";
    xfstests.flake = false;
    xfsprogs.url = "github:alberand/xfsprogs?branch=fsverity-v2&rev=86a672f111328fc16e8ea5524498020b0c1152a8";
    xfsprogs.flake = false;
  };

  outputs = { self, nixpkgs, flake-utils, nix-kernel-vm, xfstests, xfsprogs}:
  flake-utils.lib.eachDefaultSystem (system:
  let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
    root = builtins.toString ./.;
  in rec {
    devShells.default = nix-kernel-vm.lib.${system}.mkLinuxShell {
      inherit pkgs xfstests xfsprogs root;
    };
  });
}
