{
  description = "Linux Kernel development env";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.05";
    flake-utils.url = "github:numtide/flake-utils";
    nix-kernel-vm.url = "github:alberand/nix-kernel-vm";
    nix-kernel-vm.inputs.nixpkgs.follows = "nixpkgs";
    xfstests.url = "github:alberand/xfstests?rev=d0653ace57b81b1cbec4445084e4e6c9b26fab94";
    xfstests.flake = false;
    xfsprogs.url = "github:alberand/xfsprogs?rev=90ea31f2319ba2e99991545ba19d35b80c07967f";
    xfsprogs.flake = false;
    kernel-config.url = "https://gist.githubusercontent.com/alberand/02a8ba4cdc53aaeb6c569c316d57cca4/raw/70e3827b1aa0962023de822233c74de0a1b51c5d/.config";
    kernel-config.flake = false;
    xfstests-config.url = "https://gist.githubusercontent.com/alberand/85fa4d7e0929902ef5d303ae1de5cc8a/raw/1b032cf4e41859ad97ded918b39a311dff90f13e/xfstests-config";
    xfstests-config.flake = false;
  };

  outputs = { self, nixpkgs, flake-utils, nix-kernel-vm, xfstests, xfsprogs,
    kernel-config, xfstests-config }:
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
          version = "6.6.0-rc3";
          allowImportFromDerivation = true;
          src = pkgs.fetchFromGitHub {
            owner = "alberand";
            repo = "linux";
            rev = "3b556a9122c9d95e8d03452fb57ebe9bfbe36865";
            sha256 = "sha256-J89W5j3j0ydayIQoiw7z7O72ZM+SxgtyPVgDdsOaDPo=";
          };
          configfile = kernel-config;
          #config = {
            #CONFIG_AUTOFS4_FS = "y";
            #CONFIG_VIRTIO_BLK = "y";
            #CONFIG_VIRTIO_PCI = "y";
            #CONFIG_VIRTIO_NET = "y";
            #CONFIG_VIRTIO_BALLOON = "y";
            #CONFIG_VIRTIO_CONSOLE = "y";
            #CONFIG_EXT4_FS = "y";
            #CONFIG_NET_9P_VIRTIO = "y";
            #CONFIG_9P_FS = "y";
            #CONFIG_BLK_DEV = "y";
            #CONFIG_PCI = "y";
            #CONFIG_NETDEVICES = "y";
            #CONFIG_NET_CORE = "y";
            #CONFIG_INET = "y";
            #CONFIG_NETWORK_FILESYSTEMS = "y";
            #CONFIG_SERIAL_8250_CONSOLE = "y";
            #CONFIG_SERIAL_8250 = "y";
            #CONFIG_OVERLAY_FS = "y";
            #CONFIG_DEVTMPFS = "y";
            #CONFIG_CGROUPS = "y";
            #CONFIG_SIGNALFD = "y";
            #CONFIG_TIMERFD = "y";
            #CONFIG_EPOLL = "y";
            #CONFIG_SYSFS = "y";
            #CONFIG_PROC_FS = "y";
            #CONFIG_FHANDLE = "y";
            #CONFIG_CRYPTO_USER_API_HASH = "y";
            #CONFIG_CRYPTO_HMAC = "y";
            #CONFIG_CRYPTO_SHA256 = "y";
            #CONFIG_DMIID = "y";
            #CONFIG_TMPFS_POSIX_ACL = "y";
            #CONFIG_TMPFS_XATTR = "y";
            #CONFIG_SECCOMP = "y";
            #CONFIG_TMPFS = "y";
            #CONFIG_BLK_DEV_INITRD = "y";
            #CONFIG_MODULES = "y";
            #CONFIG_BINFMT_ELF = "y";
            #CONFIG_UNIX = "y";
            #CONFIG_INOTIFY_USER = "y";
            #CONFIG_NET = "y";
            ## SCSI
            #CONFIG_SCSI = "y";
            #CONFIG_DMA = "y";
            #CONFIG_SG_POOL = "y";
            #CONFIG_SCSI_COMMON = "y";
            #CONFIG_BLK_DEV_BSG_COMMON  = "y";
            #CONFIG_SCSI_LOWLEVEL = "y";
            #CONFIG_SCSI_DEBUG = "y";
          #};
        }));

        # Let's enable xfstests service
        programs.xfstests = {
          enable = true;
          src = xfstests;
          sharedir = "/root/vmtest";
          autoshutdown = false;
          testconfig = xfstests-config;
          test-dev = "/dev/sda";
          scratch-dev = "/dev/sdb";
          arguments = "-r -g all -x recoveryloop,dangerous_repair,dangerous_bothrepair,dangerous_online_repair,dangerous_norepair,broken,deprecated,dangerous_fuzzers,dangerous_scrub";
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
        test-disk = "/dev/vda";
        scratch-disk = "/dev/vdb";
        user-modules = modules;
      };
    };

    devShells.default = nix-kernel-vm.lib.${system}.mkLinuxShell {
      inherit pkgs root;

      qemu-options = [
        "-hdb /dev/sda4"
        "-hdc /dev/sda5"
      ];

      user-modules = modules;
      packages = [
        nix-kernel-vm.packages.${system}.deploy
      ];
    };
  });
}
