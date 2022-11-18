with import <nixpkgs> {};
{ pkgs ? import <nixpkgs> {} }:

stdenv.mkDerivation {
  name = "ws-tcp-proxy";
  src = ./.;

  buildInputs = [ git libtool autoconf automake autogen gnumake cmake clang ];
}
