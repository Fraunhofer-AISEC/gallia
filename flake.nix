# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: CC0-1.0

{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
  };

  outputs = { self, nixpkgs }:
    with import nixpkgs { system = "x86_64-linux"; };
    let pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in {
      devShell.x86_64-linux = pkgs.mkShell {
        buildInputs = [ pkgs.python310 pkgs.python310Packages.poetry ];
        shellHook = ''
          LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [stdenv.cc.cc]}
        '';
      };
      formatter.x86_64-linux = pkgs.nixpkgs-fmt;
    };
}
