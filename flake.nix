{
  description = "Linux Kernel development env";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nix-kernel-vm.url = "github:alberand/nix-kernel-vm";
    xfstests.url = "git+file:/home/alberand/Projects/xfstests-dev?branch=fsverity-v2&shallow=1";
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
      inherit pkgs root;

      user-modules = [
        ({config, pkgs, ...}: {

            # Let's enable xfstests service
            programs.xfstests = {
              enable = true;
              src = xfstests;
              autoshutdown = false;
              testconfig = ./xfstests-config;
              arguments = "-s xfs_1k -s xfs_4k generic/572 generic/574";
              #arguments = "-s xfs_4k -s xfs_4k_quota -g verity";
              #arguments = "-s xfs_4k generic/572 generic/574";
              pre-test-hook = ''
                  # User wants to run shell script instead of fstests
                  if [[ -f /root/vmtest/test.sh ]]; then
                    chmod u+x /root/vmtest/test.sh
                    ${pkgs.bash}/bin/bash /root/vmtest/test.sh
                    exit $?
                  fi

                  # Handle case when there's no modules glob -> empty
                  shopt -s nullglob
                  for module in /root/vmtest/modules/*.ko; do
                          ${pkgs.kmod}/bin/insmod $module;
                  done;
              '';
              post-test-hook = ''
                  # Handle case when there's no modules glob -> empty
                  shopt -s nullglob
                  for module in /root/vmtest/modules/*.ko; do
                          if cat /proc/modules | grep -c "$module"; then
                            ${pkgs.kmod}/bin/rmmod $module;
                          fi
                  done;
              '';
            };

            # Let's also include specific version of xfsprogs
            nixpkgs.overlays = [
              (self: super: {
                xfsprogs = super.xfsprogs.overrideAttrs (prev: {
                  version = "git";
                  src = xfsprogs;
                });
              })
            ];

            # Let's append real hardware to the QEMU run by "vmtest" command
            virtualisation = {
              qemu = {
                networkingOptions = [
                  "-hdc /dev/sda4 -hdd /dev/sda5 -serial mon:stdio"
                ];
              };
            };
          })
        ];
    };
  });
}
