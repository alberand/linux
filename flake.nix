{
  description = "Linux Kernel development env";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nix-kernel-vm.url = "github:alberand/nix-kernel-vm";
    xfstests.url = "git+file:/home/alberand/Projects/xfstests-dev?branch=fsverity-v2&shallow=1";
    xfstests.flake = false;
    xfsprogs.url = "github:alberand/xfsprogs?rev=ee2abc6b88dcd1b2d826904701f0b57e59d887bf";
    xfsprogs.flake = false;
    kernel-config.url = "/home/alberand/Projects/xfs-verity-v3/.config";
    kernel-config.flake = false;
    xfstests-config.url = "/home/alberand/Projects/xfs-verity-v3/xfstests-config";
    xfstests-config.flake = false;
  };

  outputs = { self, nixpkgs, flake-utils, nix-kernel-vm, xfstests, xfsprogs,
    kernel-config, xfstests-config}:
  flake-utils.lib.eachDefaultSystem (system:
  let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
    root = builtins.toString ./.;
    modules = [
      ({config, pkgs, ...}: {
        environment.systemPackages = with pkgs; [
          btrfs-progs
          f2fs-tools
          keyutils
        ];

        boot.kernelPackages = (pkgs.linuxPackagesFor (pkgs.callPackage
        pkgs.linuxManualConfig {
          inherit (pkgs) stdenv;
          version = "6.5.0-rc4";
          allowImportFromDerivation = true;
          src = pkgs.fetchFromGitHub {
            owner = "alberand";
            repo = "linux";
            rev = "3a27a5bd6d7d71f60189fcd0ba32fa91cc939fcb";
            sha256 = "sha256-35nbE5QoVdm8S1xksmMefwtoczQGlooTHKcqxADKjUc=";
          };
          configfile = kernel-config;
          config = {
            CONFIG_AUTOFS4_FS = "y";
            CONFIG_VIRTIO_BLK = "y";
            CONFIG_VIRTIO_PCI = "y";
            CONFIG_VIRTIO_NET = "y";
            CONFIG_EXT4_FS = "y";
            CONFIG_NET_9P_VIRTIO = "y";
            CONFIG_9P_FS = "y";
            CONFIG_BLK_DEV = "y";
            CONFIG_PCI = "y";
            CONFIG_NETDEVICES = "y";
            CONFIG_NET_CORE = "y";
            CONFIG_INET = "y";
            CONFIG_NETWORK_FILESYSTEMS = "y";
            CONFIG_SERIAL_8250_CONSOLE = "y";
            CONFIG_SERIAL_8250 = "y";
            CONFIG_OVERLAY_FS = "y";
            CONFIG_DEVTMPFS = "y";
            CONFIG_CGROUPS = "y";
            CONFIG_SIGNALFD = "y";
            CONFIG_TIMERFD = "y";
            CONFIG_EPOLL = "y";
            CONFIG_SYSFS = "y";
            CONFIG_PROC_FS = "y";
            CONFIG_FHANDLE = "y";
            CONFIG_CRYPTO_USER_API_HASH = "y";
            CONFIG_CRYPTO_HMAC = "y";
            CONFIG_CRYPTO_SHA256 = "y";
            CONFIG_DMIID = "y";
            CONFIG_TMPFS_POSIX_ACL = "y";
            CONFIG_TMPFS_XATTR = "y";
            CONFIG_SECCOMP = "y";
            CONFIG_TMPFS = "y";
            CONFIG_BLK_DEV_INITRD = "y";
            CONFIG_MODULES = "y";
            CONFIG_BINFMT_ELF = "y";
            CONFIG_UNIX = "y";
            CONFIG_INOTIFY_USER = "y";
            CONFIG_NET = "y";
          };
        }));

        # Let's enable xfstests service
        programs.xfstests = {
          enable = true;
          src = xfstests;
          sharedir = "/root/vmtest";
          autoshutdown = false;
          testconfig = xfstests-config;
          arguments = "-g auto";
        };

        # Let's also include specific version of sprogs
        nixpkgs.overlays = [
          (self: super: {
            xfsprogs = super.xfsprogs.overrideAttrs (prev: {
              version = "git";
              src = xfsprogs;
            });
          })
        ];
      })
    ];
  in rec {
    packages = {
      iso = nix-kernel-vm.lib.${system}.mkIso {
        inherit pkgs;
        user-modules = modules;
      };
    };

    devShells.default = nix-kernel-vm.lib.${system}.mkLinuxShell {
      inherit pkgs root;

      qemu-options = [
        "-hdc /dev/sdb4 -hdd /dev/sdb5 -serial mon:stdio"
      ];

      user-modules = modules;
      packages = [
        nix-kernel-vm.packages.${system}.deploy
      ];
    };
  });
}
