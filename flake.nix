# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: CC0-1.0

{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    # Just use the poetry package once it is on 1.2.
    poetry2nix.url = "github:nix-community/poetry2nix";
  };

  outputs = { self, nixpkgs, poetry2nix }:
    with import nixpkgs { system = "x86_64-linux"; };
    let pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in {
      devShell.x86_64-linux = pkgs.mkShell {
        buildInputs = [ pkgs.python310 poetry2nix.packages.x86_64-linux.poetry ];
        shellHook = ''
          LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [stdenv.cc.cc]}
        '';
      };
      formatter.x86_64-linux = pkgs.nixpkgs-fmt;
    };
}
